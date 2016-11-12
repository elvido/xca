/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2012 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __PKI_BASE_H
#define __PKI_BASE_H

#include <openssl/err.h>
#include <QString>
#include <QListView>
#include <QtSql>
#include "asn1time.h"
#include "pkcs11_lib.h"
#include "db.h"
#include "base.h"
#include "headerlist.h"

#define __ME QString("(%1:%2)").arg(getClassName()).arg(getIntName())
#define pki_openssl_error() _openssl_error(__ME, C_FILE, __LINE__)
#define pki_ign_openssl_error() _ign_openssl_error(__ME, C_FILE, __LINE__)

class pki_base : public QObject
{
		Q_OBJECT

	public: /* static */
		static int suppress_messages;
		static QRegExp limitPattern;
		static QString rmslashdot(const QString &fname);
		static unsigned hash(QByteArray ba);

	protected:
		QVariant sqlItemId;
		QString desc, comment;
		a1time insertion_date;
		enum pki_type pkiType;
		/* model data */
		pki_base *parent;
		void my_error(const QString myerr) const;
		void fopen_error(const QString fname);

	public:
		enum msg_type {
			msg_import,
			msg_delete,
			msg_delete_multi,
			msg_create,
		};
		QList<pki_base*> childItems;

		pki_base(const QString d = "", pki_base *p = NULL);
		virtual ~pki_base();

		QString getIntName() const
		{
			return desc;
		}
		virtual QString comboText() const;
		QString getUnderlinedName() const
		{
			return getIntName().replace(
				QRegExp("[ &;`/\\\\]+"), "_");
		}
		void setIntName(const QString &d)
		{
			desc = d;
		}
		QString getComment() const
		{
			return comment;
		}
		void setComment(QString c)
		{
			comment = c;
		}
		QVariant getSqlItemId()
		{
			return sqlItemId;
		}
		enum pki_type getType() const
		{
			return pkiType;
		}
		virtual QByteArray i2d();
		virtual bool compare(pki_base *);
		virtual QString getMsg(msg_type msg);
		virtual const char *getClassName() const;

		/* Tree View management */
		void setParent(pki_base *p);
		virtual pki_base *getParent();
		pki_base *child(int row);
		void append(pki_base *item);
		void insert(int row, pki_base *item);
		int childCount();
		pki_base *iterate(pki_base *pki = NULL);
		void takeChild(pki_base *pki);
		pki_base *takeFirst();

		/* Token handling */
		virtual void deleteFromToken();
		virtual void deleteFromToken(slotid);
		virtual int renameOnToken(slotid, QString);

		/* Import / Export management */
		virtual BIO *pem(BIO *, int format=0);
		virtual void fromPEM_BIO(BIO *, QString);
		void fwrite_ba(FILE *fp, QByteArray ba, QString fname);
		virtual void fload(const QString);
		virtual void writeDefault(const QString);

		/* Old database management methods */
		virtual void fromData(const unsigned char *, db_header_t *) {};
		/* Qt Model-View methods */
		virtual QVariant bg_color(dbheader *hd)
		{
			(void)hd;
			return QVariant();
		}
		int row() const;
		virtual QVariant column_data(dbheader *hd);
		virtual QVariant getIcon(dbheader *hd);
		virtual bool visible();


		/* SQL management methods */
		QSqlError insertSql();
		virtual QSqlError insertSqlData()
		{
			return QSqlError();
		}
		QSqlError deleteSql();
		virtual QSqlError deleteSqlData()
		{
			return QSqlError();
		}
		virtual QSqlError restoreSql(QVariant sqlId);
		QSqlError sqlItemNotFound(QVariant sqlId) const;
		unsigned hash();
};

Q_DECLARE_METATYPE(pki_base *);
#endif
