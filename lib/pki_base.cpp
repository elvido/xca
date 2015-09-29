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
	class_name = "pki_base";
	parent = p;
	childItems.clear();
	dataVersion=0;
	pkiType=none;
}

pki_base::~pki_base(void)
{
	while (childItems.size() > 0)
		delete takeFirst();
}

QString pki_base::getIntName() const
{
	return desc;
}

QString pki_base::getUnderlinedName() const
{
	return getIntName().replace(QRegExp("[ &;`/\\\\]+"), "_");
}

bool pki_base::visible()
{
	if (limitPattern.isEmpty())
		return true;
	return getIntName().contains(limitPattern);
}

QString pki_base::getClassName()
{
	QString x = class_name;
	return x;
}

void pki_base::setIntName(const QString &d)
{
	desc = d;
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
		throw errorEx(error, class_name);
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

	q.exec("BEGIN TRANSACTION");
	e = q.lastError();
	if (!e.isValid()) {
		q.prepare("INSERT INTO items "
			  "(id, name, type, version, comment) "
			  "VALUES (NULL, ?, ?, ?, ?)");
		q.bindValue(0, getIntName());
		q.bindValue(1, getType());
		q.bindValue(2, getVersion());
		q.bindValue(3, getComment());
		q.exec();
		e = q.lastError();
		if (!e.isValid()) {
			sqlItemId = q.lastInsertId();
			e = insertSqlData();
			if (!e.isValid()) {
				q.exec("COMMIT");
			}
		}
	}
	if (e.isValid())
		q.exec("ROLLBACK");
	return e;
}

QSqlError pki_base::restoreSql(QVariant sqlId)
{
	QSqlQuery q;
	QSqlError e;

	q.prepare("SELECT (name, version, comment) "
			"FROM items WHERE id=?");
	q.bindValue(0, sqlId);
	q.exec();
	e = q.lastError();
	if (e.isValid())
		return e;
	if (!q.first())
		return QSqlError(QString("XCA database inconsistent"),
				QString("Item not found %1 %2")
					.arg(class_name).arg(sqlId.toString()),
				QSqlError::UnknownError);

	desc = q.value(0).toString();
	sqlDataVersion = q.value(1).toInt();
	comment = q.value(2).toString();
	return e;
}

QSqlError pki_base::deleteSql()
{
	QSqlQuery q;
	QString insert;
	QSqlError e;

	if (!sqlItemId.isValid()) {
		q.prepare("SELECT id FROM items WHERE name=?");
		q.bindValue(0, getIntName());
		q.exec();
		e = q.lastError();
		if (e.isValid())
			return e;
		if (q.first())
			sqlItemId = q.value(0);
		else
			return QSqlError();
	}
	q.exec("BEGIN TRANSACTION");
	e = q.lastError();
	if (!e.isValid()) {
		q.prepare("DELETE FROM items WHERE id=?");
		q.bindValue(0, sqlItemId);
		q.exec();
		e = q.lastError();
		if (!e.isValid()) {
			e = deleteSqlData();
			if (!e.isValid()) {
				q.exec("COMMIT");
			}
		}
	}
	if (e.isValid())
		q.exec("ROLLBACK");
	return e;
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
	childItems.takeAt(pki->row());
}

pki_base *pki_base::takeFirst()
{
	return childItems.takeFirst();
}

QVariant pki_base::column_data(dbheader *hd)
{
	switch (hd->id) {
	case HD_internal_name:
		return QVariant(getIntName());
	}
	return QVariant();
}

QVariant pki_base::getIcon(dbheader *hd)
{
	(void)hd;
	return QVariant();
}

uint32_t pki_base::intFromData(QByteArray &ba)
{
	/* For import "oldFromData" use the endian dependent version */
	uint32_t ret;
	if ((unsigned)(ba.count()) < sizeof(uint32_t)) {
		ba.clear();
		return 0;
	}
	memcpy(&ret, ba.constData(), sizeof(uint32_t));
	ba = ba.mid(sizeof(uint32_t));
	return ret;
}

bool pki_base::compare(pki_base *refcrl)
{
	bool ret;
	ret = (i2d() == refcrl->i2d());
	pki_openssl_error();
	return ret;
}

unsigned pki_base::hash()
{
	QByteArray ba = i2d();
	unsigned char md[EVP_MAX_MD_SIZE];

	SHA1((const unsigned char *)ba.constData(), ba.length(), md);

	return (((unsigned)md[0]     ) | ((unsigned)md[1]<<8L) |
		((unsigned)md[2]<<16L) | ((unsigned)md[3]<<24L)
		) & 0xffffffffL;
}
