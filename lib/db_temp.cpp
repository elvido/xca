/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2001 - 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */


#include "db_temp.h"
#include "func.h"
#include <widgets/NewX509.h>
#include <widgets/XcaDialog.h>
#include <widgets/MainWindow.h>
#include <QFileDialog>
#include <QDir>
#include <QContextMenuEvent>
#include <QAction>
#include <QInputDialog>
#include <QMessageBox>

db_temp::db_temp(MainWindow *mw)
	:db_x509name(mw)
{
	class_name = "templates";
	sqlHashTable = "templates";
	pkitype << tmpl;

	updateHeaders();
	loadContainer();

	QDir dir;
	if (!dir.cd(getPrefix()))
		return;
	dir.setFilter(QDir::Files | QDir::NoSymLinks);
	QFileInfoList list = dir.entryInfoList();
	load_temp l;
	pki_temp *tmpl = new pki_temp(tr("Empty template"));
	tmpl->setAsPreDefined();
	predefs << tmpl;

	for (int i = 0; i < list.size(); ++i) {
		QFileInfo fileInfo = list.at(i);
		QString name = getPrefix() + QDir::separator() +
				fileInfo.fileName();
		if (!name.endsWith(".xca", Qt::CaseInsensitive))
			continue;
		try {
			tmpl = (pki_temp*)l.loadItem(name);
			if (tmpl) {
				tmpl->setAsPreDefined();
				predefs << tmpl;
			}
		} catch(errorEx &err) {
			XCA_WARN(tr("Bad template: %1").arg(name));
		}
	}
}

dbheaderList db_temp::getHeaders()
{
	dbheaderList h = db_x509name::getHeaders();
	h << new dbheader(HD_temp_type, true, tr("Type"));
	return h;
}

db_temp::~db_temp()
{
	while (!predefs.isEmpty())
		delete predefs.takeFirst();
}

pki_base *db_temp::newPKI(enum pki_type type)
{
	(void)type;
	return new pki_temp("");
}

QList<pki_base *> db_temp::getDescPredefs()
{
	return predefs << sqlSELECTpki("SELECT item FROM templates");;
}

bool db_temp::runTempDlg(pki_temp *temp)
{
	NewX509 *dlg = new NewX509(mainwin);
	emit connNewX509(dlg);

	dlg->setTemp(temp);
	if (!dlg->exec()) {
		delete dlg;
		return false;
	}
	dlg->toTemplate(temp);
	delete dlg;
	return true;
}

void db_temp::newItem()
{
	pki_temp *temp = NULL;
	QString type;

	itemCombo *ic = new itemCombo(NULL);
	ic->insertPkiItems(predefs);
	XcaDialog *dlg = new XcaDialog(mainwin, tmpl, ic,
				tr("Preset Template values"), QString());
//	dlg->buttonBox->setStandardButtons(QDialogButtonBox::Ignore |
//					   QDialogButtonBox::Ok |
//					   QDialogButtonBox::Cancel);
	if (dlg->exec()) {
		temp = new pki_temp((pki_temp*)ic->currentPkiItem());
		if (temp) {
			temp->setIntName("--");
			if (runTempDlg(temp)) {
				insertPKI(temp);
				createSuccess(temp);
			}
		}
	}
	delete dlg;
}
void db_temp::showPki(pki_base *pki)
{
	alterTemp(static_cast<pki_temp *>(pki));
}

void db_temp::load()
{
	load_temp l;
	load_default(l);
}

void db_temp::store(QModelIndex index)
{
	if (!index.isValid())
		return;

	pki_temp *temp = static_cast<pki_temp*>(index.internalPointer());

	QString fn = mainwin->getPath() + QDir::separator() +
		temp->getUnderlinedName() + ".xca";
	QString s = QFileDialog::getSaveFileName(mainwin,
		tr("Save template as"),	fn,
		tr("XCA templates ( *.xca);; All files ( * )"));
	if (s.isEmpty())
		return;
	s = nativeSeparator(s);
	mainwin->setPath(s.mid(0, s.lastIndexOf(QRegExp("[/\\\\]")) ));
	try {
		temp->writeTemp(s);
	}
	catch (errorEx &err) {
		MainWindow::Error(err);
	}
}

bool db_temp::alterTemp(pki_temp *temp)
{
	if (!runTempDlg(temp))
		return false;
	updatePKI(temp);
	return true;
}
