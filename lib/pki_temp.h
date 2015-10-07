/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2011 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_TEMP_H
#define __PKI_TEMP_H

#include "pki_base.h"
#include "x509name.h"
#include "asn1time.h"
#include "pki_x509super.h"

#define D5 "-----"
#define PEM_STRING_XCA_TEMPLATE "XCA TEMPLATE"

class pki_temp: public pki_x509name
{
		Q_OBJECT
	protected:
		static QList<QString> tmpl_keys;
		int dataSize();
		void try_fload(QString fname, const char *mode);
		bool pre_defined;
		x509name xname;
		QMap<QString, QString> settings;
		QString adv_ext;
		void fromExtList(extList *el, int nid, const char *item);

	public:
		static QPixmap *icon;

		// methods
		const char *getClassName() const;
		QString getSetting(QString key)
		{
			return settings[key];
		}
		pki_temp(const pki_temp *pk);
		pki_temp(const QString d = QString());
		void fload(const QString fname);
		void writeDefault(const QString fname);
		~pki_temp();
		void fromData(const unsigned char *p, int size, int version);
		void old_fromData(const unsigned char *p, int size, int version);
		void fromData(const unsigned char *p, db_header_t *head );
		void fromData(QByteArray &ba, int version);
		void setAsPreDefined()
		{
			pre_defined = true;
		}
		QString comboText() const;
		QByteArray toData();
		bool compare(pki_base *ref);
		void writeTemp(QString fname);
		QVariant getIcon(dbheader *hd);
		QString getMsg(msg_type msg);
		x509name getSubject() const;
		void setSubject(x509name n)
		{
			xname = n;
		}
		BIO *pem(BIO *b, int format);
		QByteArray toExportData();
		void fromPEM_BIO(BIO *, QString);
		void fromExportData(QByteArray data);
		extList fromCert(pki_x509super *cert_or_req);
};

#endif
