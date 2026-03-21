# Stellar Wallet Kit

**Documentation:** https://stellarwalletskit.dev/
```

# Start the kit

import { StellarWalletsKit } from "@creit-tech/stellar-wallets-kit/sdk";
import { defaultModules } from '@creit-tech/stellar-wallets-kit/modules/utils';

StellarWalletsKit.init({modules: defaultModules()});

# Create Auth / Login button

const buttonWrapper = document.querySelector('#buttonWrapper');
StellarWalletsKit.createButton(buttonWrapper);

# Sign transaction

const {address} = await StellarWalletsKit.getAddress();

const {signedTxXdr} = await StellarWalletsKit.signTransaction(tx.toXDR(), {
  networkPassphrase: Networks.PUBLIC,
  address,
});

console.log("Signed Transaction:", signedTxXdr);
```

## How to build a transaction

https://stellar.github.io/js-stellar-sdk/index.html
https://github.com/stellar/js-stellar-sdk


```
const StellarSdk = require('@stellar/stellar-sdk');
// Set the network (Testnet for development, Public for production)
StellarSdk.Network.useTestNetwork();
const server = new StellarSdk.Server('https://horizon-testnet.stellar.org'); //

// Replace with your actual secret keys and public keys
const sourceSecretKey = 'YOUR_SOURCE_ACCOUNT_SECRET_KEY';
const destinationPublicKey = 'DESTINATION_ACCOUNT_PUBLIC_KEY';

const sourceKeypair = StellarSdk.Keypair.fromSecret(sourceSecretKey);
const sourcePublicKey = sourceKeypair.publicKey();

// Load the account details from the network to get the current sequence number
const account = await server.loadAccount(sourcePublicKey);

const transaction = new StellarSdk.TransactionBuilder(account, { fee: '100' }) // Base fee is 100 stroops
    .addOperation(StellarSdk.Operation.payment({
        destination: destinationPublicKey,
        asset: StellarSdk.Asset.native(), // Native asset is XLM
        amount: '10.5', // Amount as a string
    }))
    .addMemo(StellarSdk.Memo.text('Test Payment')) // Memos are optional
    .setTimeout(30) // Set a timeout for the transaction
    .build();


// Here use Stellar Wallet Kit

transaction.sign(sourceKeypair);


// Submit transaction

try {
    const transactionResult = await server.submitTransaction(transaction);
    console.log('Success! Transaction hash:', transactionResult.hash);
} catch (e) {
    console.error('An error occurred:', e);
}
```