# -*- coding: utf-8 -*-
import sys

from PyQt5.QtCore import *
from PyQt5.QtWidgets import QDialog, QApplication, QFileDialog

from fortify_authid_fix import FortifyDummyFix
from main import Ui_Dialog


# from PyQt5.uic import loadUi


class Worker(QThread):

    def __init__(self, parent=None):
        super().__init__(parent)

    def setup(self, it, dirName):
        self.it = it
        self.dirName = dirName

    def run(self):
        self.it.do(self.dirName)


class AppWindow(QDialog):

    def __init__(self):
        super().__init__()
        # self.ui = loadUi('main.ui', self)
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.btn_select.clicked.connect(self.openFileNameDialog)
        self.msg = '請選擇 Jenkins SQL資料夾目錄，該目錄裡面有Procedures和Packages兩個子目錄。'
        self.bfmsg = ''
        self.it = None
        self.v_process = 0
        self.ui.progressBar.setValue(0)
        self.timer = QTimer()
        self.timer.timeout.connect(self.update)
        self.timer.start(1000)

    def update(self):
        if self.it:
            self.ui.progressBar.setValue(self.it.v_process)
        diffmsg = self.msg.replace(self.bfmsg, '')
        if diffmsg:
            self.ui.textBrowser.append(diffmsg)
            self.bfmsg = self.msg

    def openFileNameDialog(self):
        dirName = QFileDialog.getExistingDirectory(self, "選取資料夾")
        if dirName:
            self.log(dirName)
            self.it = FortifyDummyFix(self)

            self.thread = Worker()
            self.thread.setup(self.it, dirName)
            self.thread.start()

    def log(self, msg):
        self.msg += '\n' + msg


app = QApplication(sys.argv)
w = AppWindow()
w.show()
app.exec_()
