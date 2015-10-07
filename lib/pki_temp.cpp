/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2015 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#include "pki_temp.h"
#include "func.h"
#include "db.h"
#include "exception.h"
#include "widgets/MainWindow.h"
#include <QDir>
#include <QBuffer>
#include <QDataStream>

#define TEMPLATE_DS_VERSION (QDataStream::Qt_4_2)

QList<QString> pki_temp::tmpl_keys = QList<QString>()
	 << "subAltName"
	 << "issAltName"
	 << "crlDist"
	 << "authInfAcc"
	 << "nsCertType"
	 << "nsComment"
	 << "nsBaseUrl"
	 << "nsRevocationUrl"
	 << "nsCARevocationUrl"
	 << "nsRenewalUrl"
	 << "nsCaPolicyUrl"
	 << "nsSslServerName"
	 << "ca"
	 << "subKey"
	 << "authKey"
	 << "basicPath"
	 << "validN"
	 << "validM"
	 << "validMidn"
	 << "keyUse"
	 << "eKeyUse"
	 << "adv_ext"
	 << "noWellDefined";

QPixmap *pki_temp::icon = NULL;

pki_temp::pki_temp(const pki_temp *pk)
	:pki_x509name(pk->desc)
{
	pkiType = pk->pkiType;

	xname = pk->xname;
	settings = pk->settings;
}

pki_temp::pki_temp(const QString d)
	:pki_x509name(d)
{
	pkiType=tmpl;

	foreach(QString key, tmpl_keys) {
		settings[key] = QString();
	}
	settings["nsComment"] = "xca certificate";
	settings["validN"] = "365";
}

const char *pki_temp::getClassName() const
{
	return "pki_temp";
}

QString pki_temp::comboText() const
{
	return pre_defined ? QString("[default] ") + pki_base::comboText() :
			 pki_base::comboText();
}

QString pki_temp::getMsg(msg_type msg)
{
	/*
	 * We do not construct english sentences from fragments
	 * to allow proper translations.
	 *
	 * %1 will be replaced by the internal name of the template
	 */
	switch (msg) {
	case msg_import: return tr("Successfully imported the XCA template '%1'");
	case msg_delete: return tr("Delete the XCA template '%1'?");
	case msg_create: return tr("Successfully created the XCA template '%1'");
	/* %1: Number of ktemplates; %2: list of templatenames */
	case msg_delete_multi: return tr("Delete the %1 XCA templates: %2?");
	}
	return pki_base::getMsg(msg);
}

x509name pki_temp::getSubject() const
{
	return xname;
}

static int bitsToInt(extList &el, int nid, bool *crit)
{
	int ret = 0, i = el.idxByNid(nid);

	if (i != -1) {
		if (crit)
			*crit = el[i].getCritical();
		ASN1_BIT_STRING *bits;
		bits = (ASN1_BIT_STRING *)el[i].d2i();

		for (int j=0; j<9; j++) {
			if (ASN1_BIT_STRING_get_bit(bits, j))
				ret |= 1 << j;
		}
		el.removeAt(i);
	}
	return ret;
}

void pki_temp::fromExtList(extList *el, int nid, const char *item)
{
	QString target;
	el->genConf(nid, &target, &adv_ext);
	settings[item] = target;
}

extList pki_temp::fromCert(pki_x509super *cert_or_req)
{
	x509name n;
	extList el = cert_or_req->getV3ext();
	adv_ext.clear();

	settings["nsComment"] = "";

	n = cert_or_req->getSubject();
	foreach(QString sn, MainWindow::explicit_dn) {
		int nid =OBJ_sn2nid(CCHAR(sn));
		QString ne = n.popEntryByNid(nid);
		if (!ne.isNull())
			xname.addEntryByNid(nid, ne);
	}
	for (int i=0; i<n.entryCount(); i++) {
		int nid = n.nid(i);
		if (nid != NID_undef)
			xname.addEntryByNid(nid, n.getEntry(i));
	}

	fromExtList(&el, NID_subject_alt_name, "subAltName");
	fromExtList(&el, NID_issuer_alt_name, "issAltName");
	fromExtList(&el, NID_crl_distribution_points, "crlDist");
	fromExtList(&el, NID_info_access, "authInfAcc");
	fromExtList(&el, NID_netscape_comment, "nsComment");
	fromExtList(&el, NID_netscape_base_url, "nsBaseUrl");
	fromExtList(&el, NID_netscape_revocation_url, "nsRevocationUrl");
	fromExtList(&el, NID_netscape_ca_revocation_url, "nsCARevocationUrl");
	fromExtList(&el, NID_netscape_renewal_url, "nsRenewalUrl");
	fromExtList(&el, NID_netscape_ca_policy_url, "nsCaPolicyUrl");
	fromExtList(&el, NID_netscape_ssl_server_name, "nsSslServerName");

	QString r;
	if (el.genConf(NID_basic_constraints, &r)) {
		QStringList sl = r.split(",");
		if (sl.contains("critical"))
			settings["bcCrit"] = "1";
		settings["ca"] = sl.contains("CA:TRUE") ? 1 : 2;
		settings["basicPath"]=sl.filter("pathlen:").join("") .mid(8,-1);
	} else {
		settings["bcCrit"] = "";
		settings["ca"] = "";
		settings["basicPath"] = "";
	}
	settings["authKey"] = el.delByNid(NID_authority_key_identifier);
	settings["subKey"] =  el.delByNid(NID_subject_key_identifier);

	int nsCT = bitsToInt(el, NID_netscape_cert_type, NULL);
	/* bit 4 is unused. Move higher bits down. */
	settings["nsCertType"] = (nsCT & 0xf) | ((nsCT & 0xf0) >> 1);

	bool keyUseCrit;
	settings["keyUse"] = QString::number(
				bitsToInt(el, NID_key_usage, &keyUseCrit));

	settings["keyUseCrit"] = keyUseCrit ? "1" : "0";
	fromExtList(&el, NID_ext_key_usage, "eKeyUse");

	el.genGenericConf(&adv_ext);
	settings["adv_ext"] = adv_ext;

	if (cert_or_req->getType() == x509) {
		pki_x509 *cert = (pki_x509*)cert_or_req;
		if (cert->getNotAfter().isUndefined()) {
			settings["noWellDefined"] = "1";
		} else {
			a1time notBefore = cert->getNotBefore();
			a1time notAfter  = cert->getNotAfter();

			if (notBefore.toPlain().endsWith("000000Z") &&
			    notAfter.toPlain().endsWith("235959Z"))
			{
				settings["validMidn"] = "1";
			}

			int diff = notBefore.daysTo(notAfter);
			settings["validM"] = "0";
			if (diff > 60) {
				settings["validM"] = "1";
				diff /= 30;
				if (diff > 24) {
					settings["validM"] = "2";
					diff /= 12;
				}
			}
			settings["validN"] = QString::number(diff);
		}
	}
	return el;
}

void pki_temp::fromData(const unsigned char *p, db_header_t *head )
{
	int version, size;

	size = head->len - sizeof(db_header_t);
	version = head->version;
	fromData(p, size, version);
}

static QString old_eKeyUse2QString(int old)
{
	QStringList sl;
	NIDlist eku_nid = *MainWindow::eku_nid;

        for (int i=0; i<eku_nid.count(); i++) {
		if (old & (1<<i)) {
			sl << OBJ_nid2sn(eku_nid[i]);
		}
	}
	return sl.join(", ");
}

void pki_temp::old_fromData(const unsigned char *p, int size, int version)
{
	QByteArray ba((const char*)p, size);

	/* destination = */ db::stringFromData(ba);
	settings["bcCrit"] = QString::number(db::boolFromData(ba));
	settings["keyUseCrit"] = QString::number(db::boolFromData(ba));
	settings["eKeyUseCrit"] = QString::number(db::boolFromData(ba));
	settings["subKey"] = QString::number(db::boolFromData(ba));
	settings["authKey"] = QString::number(db::boolFromData(ba));
	settings["ca"] = QString::number(db::intFromData(ba));
	if (version > 5) {
		settings["basicPath"] = db::stringFromData(ba);
	} else {
		settings["basicPath"] = QString::number(db::intFromData(ba));
		if (settings["basicPath"] == "0")
			settings["basicPath"] = "";
	}
	settings["validN"] = QString::number(db::intFromData(ba));
	settings["validM"] = QString::number(db::intFromData(ba));
	settings["keyUse"] = QString::number(db::intFromData(ba));
	if (version > 4) {
		settings["eKeyUse"] = db::stringFromData(ba);
	} else {
		int old = db::intFromData(ba);
		settings["eKeyUse"] = old_eKeyUse2QString(old);
	}
	settings["nsCertType"] = QString::number(db::intFromData(ba));
	settings["subAltName"] = db::stringFromData(ba);
	settings["issAltName"] = db::stringFromData(ba);
	settings["crlDist"] = db::stringFromData(ba);
	settings["nsComment"] = db::stringFromData(ba);
	settings["nsBaseUrl"] = db::stringFromData(ba);
	settings["nsRevocationUrl"] = db::stringFromData(ba);
	settings["nsCARevocationUrl"] = db::stringFromData(ba);
	settings["nsRenewalUrl"] = db::stringFromData(ba);
	settings["nsCaPolicyUrl"] = db::stringFromData(ba);
	settings["nsSslServerName"] = db::stringFromData(ba);
	xname.d2i(ba);
	settings["authInfAcc"] = db::stringFromData(ba);
	/* certPol = */ db::stringFromData(ba);
	settings["validMidn"] = QString::number(db::boolFromData(ba));
	if (version>2)
		settings["adv_ext"] = db::stringFromData(ba);
	if (version>3)
		settings["noWellDefined"] = QString::number(db::boolFromData(ba));

	if (ba.count() > 0) {
		my_error(tr("Wrong Size %1").arg(ba.count()));
	}
}

QByteArray pki_temp::toData()
{
	QByteArray ba;

	ba += xname.i2d();

	QBuffer buf(&ba);
	buf.open(QIODevice::WriteOnly | QIODevice::Append);
	QDataStream out(&buf);
	out.setVersion(TEMPLATE_DS_VERSION);
	out << settings;
	buf.close();
	return ba;
}

void pki_temp::fromData(QByteArray &ba, int version)
{
	int size = ba.size();
	xname.d2i(ba);
	QBuffer buf(&ba);
	buf.open(QIODevice::ReadOnly);
	QDataStream in(&buf);
	in.setVersion(TEMPLATE_DS_VERSION);
	in >> settings;
	buf.close();
	fprintf(stderr, "Settings: %d, ba-size:%d size:%d\n",
			settings.size(), ba.size(), size);
}

void pki_temp::fromData(const unsigned char *p, int size, int version)
{
	if (version < 10) {
		old_fromData(p, size, version);
	} else {
		QByteArray ba((const char*)p, size);
		fromData(ba, version);
	}
}

QByteArray pki_temp::toExportData()
{
	QByteArray data, header;
	data = toData();
	header = db::intToData(data.count());
	header += db::intToData(10);
	header += data;
	return header;
}

void pki_temp::writeTemp(QString fname)
{
	FILE *fp = fopen_write(fname);

	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	fwrite_ba(fp, toExportData(), fname);
	fclose(fp);
}

void pki_temp::writeDefault(const QString fname)
{
	writeTemp(fname + QDir::separator() + getIntName() + ".xca");
}

BIO *pki_temp::pem(BIO *b, int format)
{
	(void)format;
	QByteArray ba = toExportData();
        if (!b)
		b = BIO_new(BIO_s_mem());
#if OPENSSL_VERSION_NUMBER < 0x10002000L
	PEM_write_bio(b, PEM_STRING_XCA_TEMPLATE, (char*)"",
		(unsigned char*)(ba.data()), ba.size());
#else
	PEM_write_bio(b, PEM_STRING_XCA_TEMPLATE, "",
		(const unsigned char*)(ba.constData()), ba.size());
#endif
	pki_openssl_error();
	return b;
}

void pki_temp::fromExportData(QByteArray data)
{
	int size, version;

	if (data.size() < (int)sizeof(uint32_t))
		my_error(tr("Template file content error (too small)"));

	size = db::intFromData(data);
	version = db::intFromData(data);
	fromData((const unsigned char*)data.constData(),
		data.size(), version);
}

void pki_temp::try_fload(QString fname, const char *mode)
{
	FILE *fp = fopen(QString2filename(fname), mode);
	char buf[4096];
	QByteArray ba;
	BIO *b;

	if (fp == NULL) {
		fopen_error(fname);
		return;
	}
	b = BIO_new(BIO_s_file());
	pki_openssl_error();
	BIO_set_fp(b,fp,BIO_NOCLOSE);
	try {
		fromPEM_BIO(b, fname);
		BIO_free(b);
		return;
	} catch (errorEx &err) {
		BIO_free(b);
		fseek(fp, 0, SEEK_SET);
	}
	while (1) {
		size_t ret = fread(buf, 1, sizeof buf, fp);
		ba.append(buf, ret);
		if (ret < sizeof buf)
			break;
	}
	int err = ferror(fp);
	fclose(fp);
	if (err) {
		my_error(tr("Template file content error (too small): %1").
			arg(fname));
	}
	fromExportData(ba);
	setIntName(rmslashdot(fname));
}

void pki_temp::fload(QString fname)
{
	try {
		try_fload(fname, "rb");
	} catch (errorEx &err) {
#if defined(_WIN32)
		/* Try again in ascii mode on Windows
		 * to support pre 1.1.0 template exports */
		try_fload(fname, "r");
#else
		throw err;
#endif
	}
}

void pki_temp::fromPEM_BIO(BIO *bio, QString name)
{
	QByteArray ba;
	QString msg;
	char *nm = NULL, *header = NULL;
        unsigned char *data = NULL;
	long len;

	PEM_read_bio(bio, &nm, &header, &data, &len);

	if (ign_openssl_error())
		throw errorEx(tr("Not a PEM encoded XCA Template"),
			getClassName());

	if (!strcmp(nm, PEM_STRING_XCA_TEMPLATE)) {
		ba = QByteArray::fromRawData((char*)data, len);
		fromExportData(ba);
		setIntName(rmslashdot(name));
	} else {
		msg = tr("Not an XCA Template, but '%1'").arg(nm);
	}
	OPENSSL_free(nm);
	OPENSSL_free(header);
	OPENSSL_free(data);
	if (!msg.isEmpty())
		my_error(msg);
}

pki_temp::~pki_temp()
{
}

bool pki_temp::compare(pki_base *)
{
	// we don't care if templates with identical contents
	// are stored in the database ...
	return false;
}

QVariant pki_temp::getIcon(dbheader *hd)
{
	return hd->id == HD_internal_name ? QVariant(*icon) : QVariant();
}
