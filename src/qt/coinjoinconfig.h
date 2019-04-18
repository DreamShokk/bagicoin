#ifndef COINJOINDARKSENDCONFIG_H
#define COINJOINDARKSENDCONFIG_H

#include <QDialog>

namespace Ui {
    class CoinJoinConfig;
}
class WalletModel;

/** Multifunctional dialog to ask for passphrases. Used for encryption, unlocking, and changing the passphrase.
 */
class CoinJoinConfig : public QDialog
{
    Q_OBJECT

public:

    CoinJoinConfig(QWidget *parent = nullptr);
    ~CoinJoinConfig();

    void setModel(WalletModel *model);


private:
    Ui::CoinJoinConfig *ui;
    WalletModel *model;
    void configure(bool enabled, int coins, int rounds);

private Q_SLOTS:

    void clickBasic();
    void clickHigh();
    void clickMax();
};

#endif // COINJOINDARKSENDCONFIG_H
