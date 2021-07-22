#include <qt/coinjoinconfig.h>
#include <qt/forms/ui_coinjoinconfig.h>

#include <qt/bitcoinunits.h>
#include <qt/guiconstants.h>
#include <qt/optionsmodel.h>
#include <qt/walletmodel.h>

#include <QMessageBox>
#include <QPushButton>
#include <QKeyEvent>
#include <QSettings>

CoinJoinConfig::CoinJoinConfig(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CoinJoinConfig),
    model(nullptr)
{
    ui->setupUi(this);

    connect(ui->buttonBasic, &QPushButton::clicked, this, &CoinJoinConfig::clickBasic);
    connect(ui->buttonHigh, &QPushButton::clicked, this, &CoinJoinConfig::clickHigh);
    connect(ui->buttonMax, &QPushButton::clicked, this, &CoinJoinConfig::clickMax);
}

CoinJoinConfig::~CoinJoinConfig()
{
    delete ui;
}

void CoinJoinConfig::setModel(WalletModel *_model)
{
    this->model = _model;
}

void CoinJoinConfig::clickBasic()
{
    configure(true, 1000, 1);

    QString strAmount(BitcoinUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("CoinJoin Configuration"),
        tr(
            "CoinJoin was successfully set to basic (%1 and 1 parent). You can change this at any time by opening Bagicoin's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void CoinJoinConfig::clickHigh()
{
    configure(true, 1000, 2);

    QString strAmount(BitcoinUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("CoinJoin Configuration"),
        tr(
            "CoinJoin was successfully set to high (%1 and 2 parents). You can change this at any time by opening Bagicoin's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void CoinJoinConfig::clickMax()
{
    configure(true, 1000, 3);

    QString strAmount(BitcoinUnits::formatWithUnit(
        model->getOptionsModel()->getDisplayUnit(), 1000 * COIN));
    QMessageBox::information(this, tr("CoinJoin Configuration"),
        tr(
            "CoinJoin was successfully set to maximum (%1 and 3 parents). You can change this at any time by opening Bagicoin's configuration screen."
        ).arg(strAmount)
    );

    close();
}

void CoinJoinConfig::configure(bool enabled, int coins, int rounds) {

    QSettings settings;

    settings.setValue("nCoinJoinDepth", rounds);
    settings.setValue("nCoinJoinAmount", coins);

    model->coinJoinConfigChanged(rounds, coins);
}
