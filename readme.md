# Commit-Reveal Auction Protocol

Smart-contract based auction protocol using **commit-reveal bidding**,
**cryptographic hashes**, and **economic deposits**.

Developed by:

-   Roman Atanasiu
-   Dídac Casacuberta
-   Adrià Garcia
-   Marc López
-   Arnau Mas

------------------------------------------------------------------------

# Table of Contents

-   [Actors](#actors)
-   [Protocol Phases](#protocol-phases)
    -   [1. Commit Phase](#1-commit-phase)
    -   [2. Reveal Phase](#2-reveal-phase)
    -   [3. Winner Determination](#3-winner-determination)
    -   [4. Claim Phase](#4-claim-phase)
-   [Security Considerations](#security-considerations)
-   [Cryptographic Primitives](#cryptographic-primitives)
-   [Running the Demo](#running-the-demo)



------------------------------------------------------------------------

# Actors

## Owner

The owner:

-   Sells the object
-   Sets a **minimum bid**
-   Deploys the **smart contract**

Assumption:

The owner **does not trust bidders to pay**.

------------------------------------------------------------------------

## Bidders

Bidders:

-   Participate in the auction
-   Submit **hidden bids**
-   Pay a **deposit fee**

Assumption:

Bidders **trust the owner** to deliver the prize.

------------------------------------------------------------------------

# Protocol Phases

The auction is divided into **four phases**.

------------------------------------------------------------------------

# 1. Commit Phase

The auction opens to the public with a minimum bid declared by the owner. During this phase, bidders can participate by submitting a commitment to their bid.

Each bidder computes a **hash** of their bid amount and a password and sends this hash to the smart contract. The contract stores this commitment without revealing the bid value.

To participate, bidders must also send a deposit **fee** along with their commitment. This fee ensures that bidders reveal their bids later and discourages spam participation.

At the end of this phase, the contract **stops accepting new commitments**.

# 2. Reveal Phase

After the commit phase ends, bidders must reveal their bids.

To reveal a bid, the bidder submits:

-   `bid_amount`
-   `bidder_address`
-   `password`

The smart contract recomputes the hash:

    keccak256(bid_amount || bidder_address || bidder_password)

If it matches the stored commitment:

-   the bid becomes **valid**
-   the **deposit is refunded in the future**

If a bidder **does not reveal**, the bid becomes **invalid** and the
**deposit is lost**.

------------------------------------------------------------------------

# 3. Winner Determination

After the reveal phase ends, the contract processes all verified bids. Only bids that have a **valid** commitment and have been correctly revealed are considered valid.

The contract determines the **highest** valid bid. If multiple bidders submitted the same highest bid, the winner is determined by selecting the earliest commitment timestamp. 


------------------------------------------------------------------------

# 4. Claim Phase

The winning bidder must manually **claim** the auction result within a specified time window by sending the required payment to the contract.

If the winner successfully claims the item, the funds are transferred to the owner and the auction is finalized.The winner bid recives the private key and can decrypt the prize. And all deposits can be refund.

If the winner does not claim the prize within the allowed time window, the auction offers the item to the next highest valid bidder. This process can repeat until a bidder claims the item or no valid bidders remain. If a bidder does not claim the prize, it loses its deposit.

If no bidder claims the item, the auction ends without a sale.


------------------------------------------------------------------------

# Security Considerations

### Sabotage Attack

A bidder submits an extremely large bid to break the auction.

Mitigation:

-   **Deposit requirement**

### Payment Refusal

The winner refuses to pay after winning.

Mitigation:

-   **Deposit penalty**

### Fake Prize

The owner could provide a fake prize.

Mitigation:

-   **Trust assumption** (no technical solution in this protocol)

------------------------------------------------------------------------

# Cryptographic Primitives

## Hash Function (keccak256)

The protocol uses **keccak256** to implement the commit-reveal scheme.

Properties:

**Pre-image resistance**

    Given h, finding x such that hash(x) = h is infeasible

**Second pre-image resistance**

    Given x, finding x' such that hash(x) = hash(x') is infeasible

**Collision resistance**

    Finding x ≠ y where hash(x) = hash(y) is infeasible

------------------------------------------------------------------------

## Ethereum Digital Signatures

All transactions interacting with the smart contract are signed using the Ethereum account's private key. This ensures that only the owner of the address can:

- Submit a commitment
- Reveal a bid
- Claim the auction result

The signature proves that the transaction was sent by the owner of the address.


------------------------------------------------------------------------

## Economic Deposit

The protocol includes a deposit fee that bidders must send when submitting their commitment during the commit phase. This deposit is temporarily locked in the smart contract and is returned only if the bidder correctly reveals their bid during the reveal phase.
The purpose of this mechanism is to discourage malicious or non-cooperative behaviour. Without a deposit, an attacker could submit many fake commitments or refuse to reveal their bids after observing other participants. By introducing a financial penalty for not revealing the bid, the system incentivizes bidders to follow the protocol correctly.

------------------------------------------------------------------------

## RSA Encryption

Standard RSA is first used to encrypt the prize with a public key to show it to the bidders, then it is encrypted again to send it to the winning bidder, who will decrypt it with the secret key and claim the prize.

------------------------------------------------------------------------

# Running the Demo

### Owner Set-up

-Create a local server python3 -m http.server 8080 in code directory, Open http://127.0.0.1:8080/auction-frontend.html
-Click button connect wallet and connect with metamask
-Owners sets auction parameters, encrypts prize and generates keys and deploys contract, follow instructions to upload contract in remix.


### Bidders Set-up

All bidders, connect wallet and load owner’s deploy contract in auction-frontend

### Bid 

Bidders set bid and password in the bid phase, and they reveal bid and password used. In the claim phase the winner claims reward, and decrypts the prize and then all users get  the refund of the deposit
