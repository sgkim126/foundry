An account in CodeChain represents a holder of [CodeChain Coin](CodeChain-Coin.md), and a sender of transactions. The core elements of an account are:

* An identifying address such as XXX
* A sequence number, starting at 1, increases with each transaction sent from this account. No transaction can be included in a ledger unless the transaction’s sequence number matches its sender’s next sequence number.
* Ways to authorize transactions, possibly include:
  * A master key pair intrinsic to the account
