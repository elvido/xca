/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "MainWindow.h"
#include "lib/exception.h"
#include "lib/pki_evp.h"
#include "lib/pki_scard.h"
#include "lib/entropy.h"
#include <QDir>
#include <QDebug>
#include <QStatusBar>
#include <QMessageBox>
#include <QtSql>
#include "lib/db_base.h"
#include "lib/func.h"
#include "widgets/ImportMulti.h"
#include "widgets/NewKey.h"

#if 0
	try {
		db mydb(dbfile);

		while (mydb.find(setting, QString()) == 0) {
			QString key;
			db_header_t head;
			char *p = (char *)mydb.load(&head);
			if (!p) {
				if (mydb.next())
					break;
				continue;
			}
			key = head.name;

			if (key == "workingdir")
				workingdir = p;
			else if (key == "pkcs11path")
				pkcs11path = p;
			else if (key == "default_hash")
				hashBox::setDefault(p);
			else if (key == "mandatory_dn")
				mandatory_dn = p;
			else if (key == "explicit_dn")
				explicit_dn = p;
			/* what a stupid idea.... */
			else if (key == "multiple_key_use")
				mydb.erase();
			else if (key == "string_opt")
				string_opt = p;
			else if (key == "suppress")
				mydb.erase();
			else if (key == "optionflags1")
				setOptFlags((QString(p)));
			/* Different optionflags, since setOptFlags()
			 * does an abort() for unknown flags in
			 * older versions.   *Another stupid idea*
			 * This is for backward compatibility
			 */
			else if (key == "optionflags")
				setOptFlags_old((QString(p)));
			else if (key == "defaultkey")
				NewKey::setDefault((QString(p)));
			else if (key == "mw_geometry")
				set_geometry(p, &head);
			free(p);
			if (mydb.next())
				break;
		}
	} catch (errorEx &err) {
		Error(err);
		return ret;
	}
#endif


QSqlError MainWindow::initSqlDB()
{
	QStringList sl; sl

/* The "32bit hash" in public_keys, x509super, requests, certs and crls
 * is used to faster find items in the DB by reference.
 * It consists of the first 4 bytes of a SHA1 hash.
 * Collisions are of course possible.
 *
 * All binaries are stored Base64 encoded in a column of type
 * "B64_BLOB" It is defined here by default to "VARCHAR(8000)"
 */

#define B64_BLOB "VARCHAR(10000)"

/*
 * The B64(DER(something)) function means DER encode something
 * and then Base64 encode that.
 * So finally this is PEM without newlines, header and footer
 *
 *
 *
 * Configuration settings from
 *  the Options dialog, window size, last export directory,
 *  default key type and size,
 *  column (position, sort order, visibility)
 */
<< "CREATE TABLE settings ("
	"key CHAR(20) UNIQUE, "
	"value CHAR)"
<< "INSERT INTO settings (key, value) VALUES ('schema', '1')"

/*
 * All items (keys, tokens, requests, certs, crls) are stored
 * here with the primary key.
 * The other tables containing the details reference the "id"
 * as FOREIGN KEY.
 */
<< "CREATE TABLE items("
	"id INTEGER PRIMARY KEY, "
	"name VARCHAR, "	/* Internal name of the item */
	"type INTEGER, "	/* enum pki_type */
	"comment VARCHAR)"

/*
 * Storage of public keys. Private keys and tokens also store
 * their public part here.
 */
<< "CREATE TABLE public_keys ("
	"item INTEGER, "	/* reference to items(id) */
	"type CHAR(4), "	/* RSA DSA EC (as text) */
	"hash INTEGER, "	/* 32 bit hash */
	"len INTEGER, "		/* key size in bits */
	"public "B64_BLOB", "	/* B64(DER(public key)) */
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * The private part of RSA, DSA, EC keys.
 * references to "items" and "public_keys"
 */
<< "CREATE TABLE private_keys ("
	"item INTEGER, "	/* reference to items(id) */
	"ownPass INTEGER, "	/* Encrypted by DB pwd or own pwd */
	"private "B64_BLOB", "	/* B64(Encrypt(DER(private key))) */
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * Smart cards or othe PKCS#11 tokens
 * references to "items" and "public_keys"
 */
<< "CREATE TABLE tokens ("
	"item INTEGER, "	/* reference to items(id) */
	"card_manufacturer VARCHAR(64), " /* Card location data */
	"card_serial VARCHAR(64), "	  /* as text */
	"card_model VARCHAR(64), "
	"card_label VARCHAR(64), "
	"slot_label VARCHAR(64), "
	"object_id VARCHAR(64), "	  /* Unique ID on the card */
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * Encryption and hash mechanisms supported by a token
 */
<< "CREATE TABLE token_mechanism ("
	"item INTEGER, "	/* reference to items(id) */
	"mechanism INTEGER, "	/* PKCS#11: CK_MECHANISM_TYPE */
	"FOREIGN KEY (item) REFERENCES items (id))"

/*
 * An X509 Super class, consisting of a
 *  - Distinguishd name hash
 *  - Referenced key in the database
 * used by Requests and certificates and the use-counter of keys:
 * "SELECT from x509super WHERE key=?"
 */
<< "CREATE TABLE x509super ("
	"item INTEGER, "	/* reference to items(id) */
	"subj_hash INTEGER, "	/* 32 bit hash of the Distinguished name */
	"key INTEGER, "		/* reference to the key items(id) */
	"key_hash INTEGER, "	/* 32 bit hash of the public key */
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (key) REFERENCES items (id)) "

/*
 * PKCS#10 Certificate request details
 * also takes information from the "x509super" table.
 */
<< "CREATE TABLE requests ("
	"item INTEGER, "	/* reference to items(id) */
	"hash INTEGER, "	/* 32 bit hash of the request */
	"signed INTEGER, "	/* Whether it was once signed. */
	"request "B64_BLOB", "	/* B64(DER(PKCS#10 request)) */
	"FOREIGN KEY (item) REFERENCES items (id)) "

/*
 * X509 certificate details
 * also takes information from the "x509super" table.
 * The content of the columns: hash, iss_hash, serial, ca
 * can also be retrieved directly from the certificate, but are good
 * to lurk around for faster lookup
 */
<< "CREATE TABLE certs ("
	"item INTEGER, "	/* reference to items(id) */
	"hash INTEGER, "	/* 32 bit hash of the cert */
	"iss_hash INTEGER, "	/* 32 bit hash of the issuer DN */
	"serial CHAR, "		/* Serial numbe rof the certificate */
	"issuer INTEGER, "	/* The items(id) of the issuer or NULL */
	"ca INTEGER, "		/* CA: yes / no from BasicConstraints */
	"cert "B64_BLOB", "	/* B64(DER(certificate)) */
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (issuer) REFERENCES items (id)) "

/*
 * Storage of CRLs
 */
<< "CREATE TABLE crls ("
	"item INTEGER, "	/* reference to items(id) */
	"hash INTEGER, "	/* 32 bit hash of the CRL */
	"num INTEGER, "		/* Number of revoked certificates */
	"iss_hash INTEGER, "	/* 32 bit hash of the issuer DN */
	"issuer INTEGER, "	/* The items(id) of the issuer or NULL */
	"crl "B64_BLOB", "	/* B64(DER(revocation list)) */
	"FOREIGN KEY (item) REFERENCES items (id), "
	"FOREIGN KEY (issuer) REFERENCES items (id)) "

	;
	QSqlQuery q;
	foreach(QString sql, sl) {
		fprintf(stderr, "EXEC: '%s'\n", CCHAR(sql));
		if (!q.exec(sql))
			return q.lastError();
	}
	return QSqlError();
}

QSqlError MainWindow::openSqlDB()
{
	QStringList drivers = QSqlDatabase::drivers();
	foreach( QString driver, drivers)
		fprintf(stderr, "DB driver: '%s'\n", CCHAR(driver));

	db.setDatabaseName(dbfile + ".sql");

	if (!db.open())
		return db.lastError();
	QStringList tables = db.tables();
	if (!tables.contains("items")) {
		return initSqlDB();
	}
	return QSqlError();
}

void MainWindow::set_geometry(QString geo)
{
	QStringList sl = geo.split(",");
	resize(sl[0].toInt(), sl[1].toInt());
	int i = sl[2].toInt();
	if (i != -1)
		tabView->setCurrentIndex(i);
}

void MainWindow::dbSqlError(QSqlError err)
{
	if (!err.isValid())
		err = QSqlDatabase::database().lastError();

	if (err.isValid()) {
		fprintf(stderr, "SQL ERROR: '%s'\n", CCHAR(err.text()));
		XCA_WARN(err.text());
	}
}

int MainWindow::init_database()
{
	int ret = 2;
	QSqlError err;

	qDebug("Opening database: %s", QString2filename(dbfile));
	keys = NULL; reqs = NULL; certs = NULL; temps = NULL; crls = NULL;

	Entropy::seed_rng();
	err = openSqlDB();
	dbSqlError(err);
	certView->setRootIsDecorated(db_x509::treeview);

	try {
		ret = initPass();
		if (ret == 2)
			return ret;
		keys = new db_key(this);
		reqs = new db_x509req(this);
		certs = new db_x509(this);
		temps = new db_temp(this);
		crls = new db_crl(this);
		certs->updateAfterDbLoad();
	}
	catch (errorEx &err) {
		Error(err);
		dbfile = "";
		return ret;
	}

	searchEdit->setText("");
	searchEdit->show();
	statusBar()->addWidget(searchEdit, 1);
	mandatory_dn = "";
	explicit_dn = explicit_dn_default;

	string_opt = QString("MASK:0x2002");
	ASN1_STRING_set_default_mask_asc((char*)CCHAR(string_opt));
	hashBox::resetDefault();
	pkcs11path = QString();
	workingdir = QDir::currentPath();
	setOptFlags((QString()));

	connect( keys, SIGNAL(newKey(pki_key *)),
		certs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		certs, SLOT(delKey(pki_key *)) );
	connect( keys, SIGNAL(newKey(pki_key *)),
		reqs, SLOT(newKey(pki_key *)) );
	connect( keys, SIGNAL(delKey(pki_key *)),
		reqs, SLOT(delKey(pki_key *)) );

	connect( certs, SIGNAL(connNewX509(NewX509 *)), this,
		SLOT(connNewX509(NewX509 *)) );
	connect( reqs, SIGNAL(connNewX509(NewX509 *)), this,
		SLOT(connNewX509(NewX509 *)) );

	connect( reqs, SIGNAL(newCert(pki_x509req *)),
		certs, SLOT(newCert(pki_x509req *)) );
	connect( tempView, SIGNAL(newCert(pki_temp *)),
		certs, SLOT(newCert(pki_temp *)) );
	connect( tempView, SIGNAL(newReq(pki_temp *)),
		reqs, SLOT(newItem(pki_temp *)) );

	keyView->setIconSize(pki_evp::icon[0]->size());
	reqView->setIconSize(pki_x509req::icon[0]->size());
	certView->setIconSize(pki_x509::icon[0]->size());
	tempView->setIconSize(pki_temp::icon->size());
	crlView->setIconSize(pki_crl::icon->size());

	keyView->setModel(keys);
	reqView->setModel(reqs);
	certView->setModel(certs);
	tempView->setModel(temps);
	crlView->setModel(crls);

	QSqlQuery query("SELECT key, value FROM settings");
	while (query.next()) {
		QString key = query.value(0).toString();
		QString value = query.value(1).toString();
		if (key == "workingdir")
			workingdir = value;
		else if (key == "pkcs11path")
			pkcs11path = value;
		else if (key == "default_hash")
			hashBox::setDefault(value);
		else if (key == "mandatory_dn")
			mandatory_dn = value;
		else if (key == "explicit_dn")
			explicit_dn = value;
		else if (key == "string_opt")
			string_opt = value;
		else if (key == "optionflags")
			setOptFlags(value);
		else if (key == "defaultkey")
			NewKey::setDefault(value);
		else if (key == "mw_geometry")
			set_geometry(value);
	}
	ASN1_STRING_set_default_mask_asc((char*)CCHAR(string_opt));
	if (explicit_dn.isEmpty())
		explicit_dn = explicit_dn_default;
	setWindowTitle(tr(XCA_TITLE));
	setItemEnabled(true);
	if (pki_evp::passwd.isNull())
		XCA_INFO(tr("Using or exporting private keys will not be possible without providing the correct password"));

	dbindex->setText(tr("Database") + ": " + dbfile);
	load_engine();
	return ret;
}

void MainWindow::dump_database()
{
	QString dirname = QFileDialog::getExistingDirectory(this, tr(XCA_TITLE),
			getPath());

	if (dirname.isEmpty())
		return;

	QDir d(dirname);
	if ( ! d.exists() && !d.mkdir(dirname)) {
		errorEx err("Could not create '" + dirname + "'");
		MainWindow::Error(err);
		return;
	}

	printf("Dumping to %s\n", CCHAR(dirname));
	try {
		keys->dump(dirname);
		certs->dump(dirname);
		temps->dump(dirname);
		crls->dump(dirname);
		reqs->dump(dirname);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
}

void MainWindow::undelete()
{
TRACE
	qDebug("undelete NOT WORKING!");
#if 0
	ImportMulti *dlgi = new ImportMulti(this);
	db_header_t head;
	db mydb(dbfile);

	for (mydb.first(DBFLAG_OUTDATED); !mydb.eof(); mydb.next(DBFLAG_OUTDATED)) {
		mydb.get_header(&head);
		if (head.flags & DBFLAG_DELETED) {
			pki_base *item;
			unsigned char *p = NULL;
			QString name = QString::fromUtf8(head.name);
			switch (head.type) {
			case asym_key: item = new pki_evp(name); break;
			case x509_req: item = new pki_x509req(name); break;
			case x509: item = new pki_x509(name); break;
			case revocation: item = new pki_crl(name); break;
			case tmpl: item = new pki_temp(name); break;
			case smartCard: item = new pki_scard(name); break;
			default: continue;
			}
			try {
				p = mydb.load(&head);
				item->fromData(p, &head);
				dlgi->addItem(item);
			}
			catch (errorEx &err) {
				Error(err);
				delete item;
			}
			free(p);
		}
	}
	if (dlgi->entries() > 0) {
		dlgi->execute(1);
	} else {
		XCA_INFO(tr("No deleted items found"));
	}
	delete dlgi;
#endif
}

int MainWindow::open_default_db()
{
	if (!dbfile.isEmpty())
		return 0;
	FILE *fp = fopen_read(getUserSettingsDir() +
			QDir::separator() + "defaultdb");
	if (!fp)
		return 0;

	char buff[256];
	size_t len = fread(buff, 1, 255, fp);
	fclose(fp);
	buff[len] = 0;
	dbfile = filename2QString(buff).trimmed();
	if (QFile::exists(dbfile))
		return init_database();
	dbfile = QString();
	return 0;
}

void MainWindow::default_database()
{
	QFileInfo fi(dbfile);
	QString dir = getUserSettingsDir();
	QString file = dir +QDir::separator() +"defaultdb";
	FILE *fp;
	QDir d;

	if (dbfile.isEmpty()) {
		QFile::remove(file);
		return;
	}
	d.mkpath(dir);

	fp = fopen_write(file);
	if (fp) {
		QByteArray ba;
		ba = filename2bytearray(fi.canonicalFilePath() + "\n");
		fwrite(ba.constData(), ba.size(), 1, fp);
		fclose(fp);
	}

}

QString MainWindow::getSetting(QString key)
{
	QSqlQuery q;
	q.prepare("SELECT value FROM settings WHERE key=?");
	q.bindValue(0, key);
	q.exec();
	if (q.first()) {
		return q.value(0).toString();
	}
	dbSqlError(q.lastError());
	return QString();
}

void MainWindow::storeSetting(QString key, QString value)
{
	QSqlQuery q;
	q.prepare("UPDATE settings SET value=? WHERE key=?");
	q.bindValue(0, value);
	q.bindValue(1, key);
	q.exec();
	dbSqlError(q.lastError());
	if (q.numRowsAffected() == 1)
		return;
	q.prepare("INSERT INTO settings (key, value) VALUES (?, ?)");
	q.bindValue(0, key);
	q.bindValue(1, value);
	q.exec();
	dbSqlError(q.lastError());
}

void MainWindow::close_database()
{
	QByteArray ba;
	if (!db.isOpen())
		return;

	qDebug("Closing database: %s", QString2filename(dbfile));
	QString s = QString("%1,%2,%3")
		.arg(size().width()).arg(size().height())
		.arg(tabView->currentIndex());
	storeSetting("mw_geometry", s);

	setItemEnabled(false);
	statusBar()->removeWidget(searchEdit);
	dbindex->clear();

	keyView->setModel();
	reqView->setModel();
	certView->setModel();
	tempView->setModel();
	crlView->setModel();

	if (crls)
		delete(crls);
	if (reqs)
		delete(reqs);
	if (certs)
		delete(certs);
	if (temps)
		delete(temps);
	if (keys)
		delete(keys);

	reqs = NULL;
	certs = NULL;
	temps = NULL;
	keys = NULL;

	QSqlDatabase::database().close();
	pki_evp::passwd.cleanse();
	pki_evp::passwd = QByteArray();

	if (!crls)
		return;
	crls = NULL;

	update_history(dbfile);
	pkcs11::remove_libs();
	enableTokenMenu(pkcs11::loaded());
	dbfile.clear();
}

void MainWindow::load_history()
{
	QFile file;
	QString name = getUserSettingsDir() + QDir::separator() + "dbhistory";

	file.setFileName(name);
	if (!file.open(QIODevice::ReadOnly))
		return;

	history.clear();
	while (!file.atEnd()) {
		QString name;
		char buf[1024];
		ssize_t size = file.readLine(buf, sizeof buf);
		if (size <= 0)
			break;
		name = filename2QString(buf);
		name = name.trimmed();
		if (name.size() == 0)
			continue;
		if (history.indexOf(name) == -1)
			history << name;
	}
	file.close();
	update_history_menu();
}

void MainWindow::update_history(QString fname)
{
	QFile file;
	int pos;
	QString name, dir = getUserSettingsDir();
	QDir d;

	pos = history.indexOf(fname);
	if (pos == 0)
		return; /* no changes */

	d.mkpath(dir);

	if (pos > 0)
		history.removeAt(pos);
	history.prepend(fname);
	while (history.size() > 10)
		history.removeLast();

	name = dir + QDir::separator() + "dbhistory";
	file.setFileName(name);
	if (!file.open(QIODevice::ReadWrite))
		return;

	for (pos = 0; pos < history.size(); pos++) {
		QByteArray ba = filename2bytearray(history[pos]);
		ba.append('\n');
		if (file.write(ba) <= 0)
			break;
	}
	file.close();
	update_history_menu();
}
