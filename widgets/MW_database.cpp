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

	<< "CREATE TABLE settings(key CHAR(20) UNIQUE, "
				  "value CHAR)"
	<< "INSERT INTO settings (key, value) VALUES ('schema', '1')"

	<< "CREATE TABLE items(id INTEGER PRIMARY KEY, "
				"name VARCHAR, "
				"type INTEGER, "
				"version INTEGER, "
				"comment VARCHAR)"

	<< "CREATE TABLE keys (item INTEGER, "
				"type INTEGER, "
				"der_public BLOB, "
				"len INTEGER, "
			"FOREIGN KEY (item) REFERENCES items (id))"

	<< "CREATE TABLE swkeys (item INTEGER, "
				"ownPass INTEGER, "
				"private BLOB, "
			"FOREIGN KEY (item) REFERENCES items (id))"

	<< "CREATE TABLE tokens (item INTEGER, "
				"card_manufacturer VARCHAR(64), "
				"card_serial VARCHAR(64), "
				"card_model VARCHAR(64), "
				"card_label VARCHAR(64), "
				"slot_label VARCHAR(64), "
				"object_id VARCHAR(64), "
			"FOREIGN KEY (item) REFERENCES items (id))"

	<< "CREATE TABLE token_mechanism (item INTEGER, "
					"mechanism INTEGER, "
			"FOREIGN KEY (item) REFERENCES items (id))"

	<< "CREATE TABLE x509super (item INTEGER, "
				"subj_hash INTEGER, "
				"key INTEGER, "
			"FOREIGN KEY (item) REFERENCES items (id), "
			"FOREIGN KEY (key) REFERENCES items (id)) "

	<< "CREATE TABLE requests (item INTEGER, "
				"request BLOB, "
				"signed INTEGER, "
			"FOREIGN KEY (item) REFERENCES items (id)) "

	<< "CREATE TABLE certs (item INTEGER, "
				"cert BLOB, "
				"iss_hash INTEGER, "
				"serial CHAR, "
				"fpMD5 CHAR(48), "
				"issuer INTEGER, "
				"ca INTEGER, "
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
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
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
		keys = new db_key(dbfile, this);
		reqs = new db_x509req(dbfile, this);
		certs = new db_x509(dbfile, this);
		temps = new db_temp(dbfile, this);
		crls = new db_crl(dbfile, this);
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
		fprintf(stderr, "Setting: '%s'\n", CCHAR(key));
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
		fprintf(stderr, "GET Setting: '%s' : '%s'\n",
			 CCHAR(key), CCHAR(q.value(0).toString()));
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
	if (!dbfile.isEmpty()) {
		QString s = QString("%1,%2,%3")
			.arg(size().width()).arg(size().height())
			.arg(tabView->currentIndex());
		storeSetting("mw_geometry", s);
	}
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


	try {
		int ret;
		db mydb(dbfile);
		ret = mydb.shrink( DBFLAG_OUTDATED | DBFLAG_DELETED );
		if (ret == 1)
			XCA_INFO(tr("Errors detected and repaired while deleting outdated items from the database. A backup file was created"));
		if (ret == 2)
			XCA_INFO(tr("Removing deleted or outdated items from the database failed."));
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
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
