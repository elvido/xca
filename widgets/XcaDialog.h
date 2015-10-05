/* vi: set sw=4 ts=4:
 *
 * Copyright (C) 2014 Christian Hohnstaedt.
 *
 * All rights reserved.
 */

#ifndef __XCADIALOG_H
#define __XCADIALOG_H

#include <QList>
#include <QDialog>
#include "ui_XcaDialog.h"
#include "lib/db.h"
#include "MainWindow.h"

class XcaDialog : public QDialog, public Ui::XcaDialog
{
    public:
	XcaDialog(QWidget *parent, enum pki_type type, QWidget *w,
		QString t, QString desc) : QDialog(parent)
	{
		setWindowTitle(XCA_TITLE);
		setupUi(this);

		QPixmap *icon = NULL;
		switch (type) {
		case asym_key:   icon = MainWindow::keyImg; break;
		case x509_req:   icon = MainWindow::csrImg; break;
		case x509:       icon = MainWindow::certImg; break;
		case revocation: icon = MainWindow::revImg; break;
		case tmpl:       icon = MainWindow::tempImg; break;
		case smartCard:  icon = MainWindow::scardImg; break;
		default: break;
		}
		if (icon)
			image->setPixmap(*icon);
		content->addWidget(w);
		title->setText(t);
		description->setText(desc);
	}
};

#endif
