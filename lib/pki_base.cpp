/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2013 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "func.h"
#include "pki_base.h"
#include "exception.h"
#include <QString>
#include <openssl/evp.h>
#include <openssl/sha.h>

int pki_base::suppress_messages = 0;
QRegExp pki_base::limitPattern;

pki_base::pki_base(const QString name, pki_base *p)
{
	desc = name;
	parent = p;
	childItems.clear();
	pkiType=none;
}

pki_base::~pki_base(void)
{
	while (childItems.size() > 0)
		delete takeFirst();
}

QString pki_base::comboText() const
{
	return desc;
}
void pki_base::deleteFromToken() { };
void pki_base::deleteFromToken(slotid) { };
void pki_base::writeDefault(const QString) { }
void pki_base::fromPEM_BIO(BIO *, QString) { }
void pki_base::fload(const QString) { }
int pki_base::renameOnToken(slotid, QString)
{
	return 0;
}


bool pki_base::visible()
{
	if (limitPattern.isEmpty())
		return true;
	return getIntName().contains(limitPattern);
}

QString pki_base::getMsg(msg_type msg)
{
	return tr("Internal error: Unexpected message: %1 %2")
		.arg(getClassName()).arg(msg);
}

QByteArray pki_base::i2d()
{
	return QByteArray();
}

BIO *pki_base::pem(BIO *, int format)
{
	(void)format;
	return NULL;
}

const char *pki_base::getClassName() const
{
	return "pki_base";
}

void pki_base::fopen_error(const QString fname)
{
	my_error(tr("Error opening file: '%1': %2").
			arg(fname).
			arg(strerror(errno)));
}

void pki_base::fwrite_ba(FILE *fp, QByteArray ba, QString fname)
{
	if (fwrite(ba.constData(), 1, ba.size(), fp) != (size_t)ba.size()) {
		my_error(tr("Error writing to file: '%1': %2").
			arg(fname).
			arg(strerror(errno)));
        }
}

void pki_base::my_error(const QString error) const
{
	if (!error.isEmpty()) {
		fprintf(stderr, "%s\n", CCHAR(tr("Error: ") + error));
		throw errorEx(error, getClassName());
	}
}

QString pki_base::rmslashdot(const QString &s)
{
	QByteArray a = s.toLatin1().replace("\\", "/");
	int r = a.lastIndexOf('.');
	int l = a.lastIndexOf('/');
	return s.mid(l+1,r-l-1);
}

QSqlError pki_base::insertSql()
{
	QSqlQuery q;
	QString insert;
	QSqlError e;
	insertion_date.now();

	q.prepare("INSERT INTO items "
		  "(id, name, type, date, comment) "
		  "VALUES (NULL, ?, ?, ?, ?)");
	q.bindValue(0, getIntName());
	q.bindValue(1, getType());
	q.bindValue(2, insertion_date.toPlain());
	q.bindValue(3, getComment());
	q.exec();
	e = q.lastError();
	if (!e.isValid()) {
		sqlItemId = q.lastInsertId();
		e = insertSqlData();
	}
	return e;
}

QSqlError pki_base::restoreSql(QVariant sqlId)
{
	QSqlQuery q;
	QSqlError e;

	q.prepare("SELECT name, date, comment FROM items WHERE id=?");
	q.bindValue(0, sqlId);
	q.exec();
	e = q.lastError();

	if (e.isValid())
		return e;
	if (!q.first())
		return sqlItemNotFound(sqlId);
	desc = q.value(0).toString();
	insertion_date.fromPlain(q.value(1).toString());
	comment = q.value(2).toString();
	sqlItemId = sqlId;
	return e;
}

QSqlError pki_base::deleteSql()
{
	QSqlQuery q;
	QString insert;
	QSqlError e;

	if (!sqlItemId.isValid()) {
		qDebug("INVALID sqlItemId (DELETE %s)", CCHAR(getIntName()));
			return sqlItemNotFound(QVariant());
	}
	q.prepare("DELETE FROM items WHERE id=?");
	q.bindValue(0, sqlItemId);
	q.exec();
	e = q.lastError();
	if (!e.isValid())
		e = deleteSqlData();
	return e;
}

QSqlError pki_base::sqlItemNotFound(QVariant sqlId) const
{
	return QSqlError(QString("XCA SQL database inconsistent"),
			QString("Item %2 not found %1")
				.arg(getClassName())
				.arg(sqlId.toString()),
			QSqlError::UnknownError);
}

pki_base *pki_base::getParent()
{
	return parent;
}

void pki_base::setParent(pki_base *p)
{
	parent = p;
}

pki_base *pki_base::child(int row)
{
	return childItems.value(row);
}

void pki_base::append(pki_base *item)
{
	childItems.append(item);
	item->setParent(this);
}

void pki_base::insert(int row, pki_base *item)
{
	childItems.insert(row, item);
	item->setParent(this);
}

int pki_base::childCount()
{
	return childItems.size();
}

int pki_base::row(void) const
{
	if (parent)
		return parent->childItems.indexOf(const_cast<pki_base*>(this));
	return 0;
}

pki_base *pki_base::iterate(pki_base *pki)
{
	if (pki == NULL)
		pki = (childItems.isEmpty()) ? NULL : childItems.first();
	else
		pki = childItems.value(pki->row()+1);

	if (pki) {
		return pki;
	}
	if (!parent) {
		return NULL;
	}
	return parent->iterate(this);
}

void pki_base::takeChild(pki_base *pki)
{
	fprintf(stderr, "Parent: '%s' %p %d before TAKE child: '%s'\n",
		CCHAR(getIntName()), this,
		childCount(),
		CCHAR(pki->getIntName()));
	childItems.takeAt(pki->row());
}

pki_base *pki_base::takeFirst()
{
	fprintf(stderr, "Parent: '%s' %p %d before TAKE FIRST child: '%s'\n",
		CCHAR(getIntName()), this,
		childCount(),
		CCHAR(childItems.first()->getIntName()));
	return childItems.takeFirst();
}

QVariant pki_base::column_data(dbheader *hd)
{
	switch (hd->id) {
	case HD_internal_name:
		return QVariant(getIntName());
	case HD_creation:
		return QVariant(insertion_date.toSortable());
	case HD_comment:
		return QVariant(comment.section('\n', 0, 0));
	}
	return QVariant();
}

QVariant pki_base::getIcon(dbheader *hd)
{
	(void)hd;
	return QVariant();
}

bool pki_base::compare(pki_base *ref)
{
	bool ret;
	ret = (i2d() == ref->i2d());
	pki_openssl_error();
	return ret;
}

unsigned pki_base::hash(QByteArray ba)
{
	unsigned char md[EVP_MAX_MD_SIZE];

	SHA1((const unsigned char *)ba.constData(), ba.length(), md);

	return (((unsigned)md[0]     ) | ((unsigned)md[1]<<8L) |
		((unsigned)md[2]<<16L) | ((unsigned)md[3]<<24L)
		) & 0xffffffffL;
}
unsigned pki_base::hash()
{
	return hash(i2d());
}
