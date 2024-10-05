# Blockchain Amplification Attack 

We implement our attack simulation on the top of the [SpeculativeDoS](https://github.com/AvivYaish/SpeculativeDoS). 

To reproduce our results, please do the following.
1. Clone our repository, and install Go version higher than 1.19 but lower than 1.23 on your machine. (The current go 1.23 has an issue in runtime package when you compile from the sourcecode)
2. Move to the test location. 

For Amplification attack 
```
cd modified/eth/block-validation
```

For MemPurge and Baseline attack
```
cd unmodified/eth/block-validation
``` 

3. Run the tests. For example, if you want to run TestAmplificationBasis
```
go test -v -run=TestAmplificationBasis -timeout=0s
```

## Remarks
- We aim to adhere to the experimental procedure outlined in SpeculativeDoS as closely as possible to facilitate direct comparisons between different DoS attacks. However, there have been some modifications.
- Unlike SpeculativeDoS, all transactions consist solely of basic ETH transfers. 
- We initially fund 0.99 ether to the attack accounts, while allocating a larger amount to the honest accounts. This enables the attacker to craft invalid transactions.  
- We generate 10 initial blocks based on the parameters outlined in [AllEthashProtocolChanges](https://github.com/ethereum/go-ethereum/blob/master/params/config.go#L142) and populate them with basic ETH transfers amongst honest (malicious) accounts. Each block can accommodate up to 1427 transactions, with each account sending 1 wei to the next account in a ring structure. With 80 honest or malicious accounts, each account typically has around 85-90 transactions before starting the experiments. This also allows the attacker to craft invalid transactions with previously used nonces. 
- We also ensure that the gas price for each attack transaction remains consistent across different attacks.
- We employ the same set of parameters use in Geth or SpeculativeDoS. 
- For example, the txpool size is 6334 (5120 global slots and 1024 global queue). Generally, the txpool only utilizes the global slot unless the number of accounts exceeds a certain threshold (typically more than 5120/16=320 accounts).
- Here, we test our Amplification attack on the modified node, and Baseline and MemPurge on the unmodified node. You can yield the exact same results when testing all three attacks on the modified nodes as well. 


# Tests
Below, we explain the purpose of each test and what it aims to verify.

## Modified node 
(Test location: ``modified/eth/block-validation/api_test.go``.)
We test our Amplification attack on our modified node. 

### TestAmplificationBasis
- We follow the setting from ``TestMemPurgePendingDependsOnFirst``. 
- 1 attack account. 
- The attacker sends 64 transactions with insufficient and previously used nonce (to the randomly generated accounts). 
- The modified node accepts all of invalid attack transactions and insert them into its txpool.
- If the block is mined, no attack transaction is included into the block.

### TestAmplificationEvictsMempoolOneAccount
- We adhere to the settings used in ``TestMemPurgeEvictsMempoolOneAccount``.
- 1 honest account, and 79 accounts. 
- An honest account initially sends 5120 transactions to completely fill the txpool.
- If the block were to be mined, it would include 1427 honest transactions. 1427 is the maximum number of basic transfer transactions allowed in a single block.
- Each attack account sends 64 invalid transactions with insufficient balance and past nonces.
- After the attack, some honest transactions are evicted from the txpool and replaced by the attackers. 
- If the block were to be created, no attack transactions are included in the block. This aspect distinguishes our attack from MemPurge or the Baseline approach.

### TestAmplificationEvictsMempoolMultipleAccounts
- We adhere to the settings used in ``TestMemPurgeEvictsMempoolMultipleAccounts``. 
- The test resembles ``TestAmplificationEvictsMempoolOneAccount``, but in this case, the txpool is filled by multiple honest accounts, making eviction more challenging. 
- Each honest account initially sends 64 transactions to collectively fill the txpool.
- Each attack account sends 32 invalid transactions (insufficient balance, past nonce).
- After the attack, some honest transactions are evicted and replaced by the attackers, but attack transaction is never included in the block. 

### TestAmplificationEvictsMempoolChangeNumAddr
- Same as ``TestAmplificationEvictsMempoolMultipleAccounts``, but we vary the number of attack accounts from 40 to 2000.
- Produce a csv file (``amplification_change_addr.csv``)

### TestAmplificationEvictsMempoolChangeNumTxs
- Same as ``TestAmplificationEvictsMempoolMultipleAccounts``, but we calibrate the number of attack transactions each attacker sends from 8 to 256.
- Produce a csv file (``amplification_change_txs.csv``)

### Unmodified (regular) node
(Test location: ``unmodified/eth/block-validation/api_test.go``.)

We test 1) the Baseline approach: – sending transactions with higher gas prices (i.e., naive eviction strategy), and 2) MemPurge – sending future latent transactions by extending DETER method. 

### TestBasicEvictsMempoolMultipleAccounts
- We follow the setting from ``TestMemPurgeEvictsMempoolMultipleAccounts``. 
- 80 honest accounts, and 80 attack accounts. 
- Each honest account initially sends 64 transactions to collectively fill the txpool. 
- Each attack account sends 32 (valid) attack transactions with a higher gas fees. 
- After the attack, some honest transactions are evicted and replaced by the attackers. 
- If the block were to be created, all the attack transactions would be included, indicating a high attack cost. 

### TestBasicEvictsMempoolChangeNumAddr
- Same test as ``TestBasicEvictsMempoolMultipleAccounts``, but we vary the number of attack accounts from 40 to 2000.
- Produce a csv file (``baseline_change_addr.csv``)

### TestMemPurgeEvictsMempoolChangeNumAddr
- Same test as ``TestMemPurgeEvictsMempoolMultipleAccounts`` (impelemented in SpeculativeDoS), but we vary the number of attack accounts from 40 to 2000.
- Produce a csv file (``mempurge_change_addr.csv``)

### TestAmplificationBasis
- Same test we implement in ``modified/eth/block-validation/api_test.go``
- The test should not meet the requirements here and fail to be executed in the middle; the attack transactions will always be rejected by an unmodified (regular) node's txpool.


