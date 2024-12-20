;; TrustVault - A secure multi-signature vault with NFT and conditional withdrawals
;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-SIGNATURE (err u101))
(define-constant ERR-CONDITION-NOT-MET (err u102))
(define-constant ERR-ALREADY-INITIALIZED (err u103))
(define-constant ERR-NOT-INITIALIZED (err u104))
(define-constant ERR-INSUFFICIENT-BALANCE (err u105))
(define-constant ERR-NFT-TRANSFER-FAILED (err u106))
(define-constant ERR-INVALID-NFT (err u107))
(define-constant ERR-INVALID-AMOUNT (err u108))
(define-constant ERR-INVALID-TIME (err u109))
(define-constant ERR-INVALID-PRINCIPAL (err u110))
(define-constant ERR-INVALID-REQUEST-ID (err u111))

;; Data variables
(define-data-var contract-owner principal tx-sender)
(define-data-var required-signatures uint u2)
(define-data-var vault-initialized bool false)
(define-data-var max-amount-limit uint u1000000000) ;; Set a reasonable maximum amount limit

;; Maps
(define-map authorized-signers principal bool)
(define-map vault-balances principal uint)
(define-map nft-holdings 
    { owner: principal, asset-contract: principal, token-id: uint } 
    bool
)

(define-map withdrawal-requests 
    { request-id: uint }
    { 
        stx-amount: uint,
        nft-assets: (list 10 {asset-contract: principal, token-id: uint}),
        beneficiary: principal,
        signatures: (list 20 principal),
        condition-time: uint,
        executed: bool
    }
)

;; Counter for withdrawal requests
(define-data-var request-counter uint u0)

;; SIP-009 NFT Interface
(define-trait nft-trait
    (
        (transfer (uint principal principal) (response bool uint))
        (get-owner (uint) (response principal uint))
        (get-token-uri (uint) (response (optional (string-ascii 256)) uint))
    )
)

;; Helper functions for input validation
(define-private (is-valid-amount (amount uint))
    (<= amount (var-get max-amount-limit))
)

(define-private (is-valid-time (time uint))
    (and 
        (>= time block-height)
        (<= time (+ block-height u1000000)) ;; Set reasonable future limit
    )
)

(define-private (is-valid-principal (address principal))
    (not (is-eq address (as-contract tx-sender)))
)

(define-private (is-valid-request-id (request-id uint))
    (< request-id (var-get request-counter))
)

;; Public functions
(define-public (initialize (signers (list 5 principal)) (sig-threshold uint))
    (begin
        (asserts! (not (var-get vault-initialized)) ERR-ALREADY-INITIALIZED)
        (asserts! (> sig-threshold u0) ERR-INVALID-SIGNATURE)
        (asserts! (<= sig-threshold (len signers)) ERR-INVALID-SIGNATURE)
        
        (map add-authorized-signer signers)
        (var-set required-signatures sig-threshold)
        (var-set vault-initialized true)
        (ok true)
    )
)

(define-public (deposit-stx (amount uint))
    (begin
        (asserts! (var-get vault-initialized) ERR-NOT-INITIALIZED)
        (asserts! (is-valid-amount amount) ERR-INVALID-AMOUNT)
        
        ;; Safe math: check for overflow
        (let ((current-balance (default-to u0 (map-get? vault-balances tx-sender))))
            (asserts! (<= (+ current-balance amount) (var-get max-amount-limit)) ERR-INVALID-AMOUNT)
            
            (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
            (map-set vault-balances tx-sender (+ current-balance amount))
            (ok true)
        )
    )
)

(define-public (deposit-nft (nft-contract <nft-trait>) (token-id uint))
    (begin
        (asserts! (var-get vault-initialized) ERR-NOT-INITIALIZED)
        (asserts! (is-valid-principal (contract-of nft-contract)) ERR-INVALID-PRINCIPAL)
        
        ;; Verify NFT ownership before transfer
        (try! (contract-call? nft-contract get-owner token-id))
        (try! (contract-call? nft-contract transfer 
            token-id 
            tx-sender 
            (as-contract tx-sender)))
        
        (map-set nft-holdings 
            { 
                owner: tx-sender, 
                asset-contract: (contract-of nft-contract),
                token-id: token-id 
            } 
            true)
        (ok true)
    )
)

(define-public (create-withdrawal-request 
    (stx-amount uint) 
    (nft-assets (list 10 {asset-contract: principal, token-id: uint}))
    (beneficiary principal)
    (condition-time uint))
    (let
        ((request-id (var-get request-counter)))
        (asserts! (var-get vault-initialized) ERR-NOT-INITIALIZED)
        (asserts! (is-valid-amount stx-amount) ERR-INVALID-AMOUNT)
        (asserts! (is-valid-time condition-time) ERR-INVALID-TIME)
        (asserts! (is-valid-principal beneficiary) ERR-INVALID-PRINCIPAL)
        (asserts! 
            (>= (default-to u0 (map-get? vault-balances tx-sender)) stx-amount)
            ERR-INSUFFICIENT-BALANCE)
        
        (asserts! (verify-nft-ownership nft-assets tx-sender) ERR-INVALID-NFT)
        
        (map-set withdrawal-requests
            { request-id: request-id }
            {
                stx-amount: stx-amount,
                nft-assets: nft-assets,
                beneficiary: beneficiary,
                signatures: (list tx-sender),
                condition-time: condition-time,
                executed: false
            }
        )
        (var-set request-counter (+ request-id u1))
        (ok request-id)
    )
)

(define-public (sign-withdrawal-request (request-id uint))
    (begin
        (asserts! (is-valid-request-id request-id) ERR-INVALID-REQUEST-ID)
        (let
            ((request (unwrap! (map-get? withdrawal-requests { request-id: request-id }) ERR-INVALID-SIGNATURE))
             (current-signatures (get signatures request)))
            
            (asserts! (var-get vault-initialized) ERR-NOT-INITIALIZED)
            (asserts! (is-authorized-signer tx-sender) ERR-NOT-AUTHORIZED)
            (asserts! (not (get executed request)) ERR-INVALID-SIGNATURE)
            
            (map-set withdrawal-requests
                { request-id: request-id }
                (merge request 
                    { signatures: (unwrap! (as-max-len? 
                        (append current-signatures tx-sender) u20)
                        ERR-INVALID-SIGNATURE) }
                )
            )
            (ok true)
        )
    )
)

(define-public (execute-withdrawal (request-id uint))
    (begin
        (asserts! (is-valid-request-id request-id) ERR-INVALID-REQUEST-ID)
        (let
            ((request (unwrap! (map-get? withdrawal-requests { request-id: request-id }) ERR-INVALID-SIGNATURE)))
            
            (asserts! (var-get vault-initialized) ERR-NOT-INITIALIZED)
            (asserts! (not (get executed request)) ERR-INVALID-SIGNATURE)
            (asserts! (>= block-height (get condition-time request)) ERR-CONDITION-NOT-MET)
            (asserts! 
                (>= (len (get signatures request)) (var-get required-signatures))
                ERR-INVALID-SIGNATURE)
            
            (if (> (get stx-amount request) u0)
                (try! (as-contract 
                    (stx-transfer? 
                        (get stx-amount request)
                        tx-sender
                        (get beneficiary request))))
                true)
            
            (map-set withdrawal-requests
                { request-id: request-id }
                (merge request { executed: true })
            )
            (ok true)
        )
    )
)

;; Private functions
(define-private (is-authorized-signer (signer principal))
    (default-to false (map-get? authorized-signers signer))
)

(define-private (add-authorized-signer (signer principal))
    (map-set authorized-signers signer true)
)

(define-private (verify-nft-ownership (nft-assets (list 10 {asset-contract: principal, token-id: uint})) (owner principal))
    (begin
        (fold check-nft-ownership nft-assets true)
    )
)

(define-private (check-nft-ownership (nft {asset-contract: principal, token-id: uint}) (prev-result bool))
    (and 
        prev-result
        (default-to 
            false 
            (map-get? 
                nft-holdings 
                { 
                    owner: tx-sender,
                    asset-contract: (get asset-contract nft),
                    token-id: (get token-id nft)
                }
            )
        )
    )
)

(define-public (transfer-single-nft 
    (nft-contract <nft-trait>)
    (token-id uint)
    (beneficiary principal))
    (begin
        (asserts! (is-valid-principal (contract-of nft-contract)) ERR-INVALID-PRINCIPAL)
        (asserts! (is-valid-principal beneficiary) ERR-INVALID-PRINCIPAL)
        (as-contract
            (contract-call? 
                nft-contract
                transfer
                token-id
                tx-sender
                beneficiary)))
)

;; Read-only functions
(define-read-only (get-vault-balance (owner principal))
    (default-to u0 (map-get? vault-balances owner))
)

(define-read-only (get-withdrawal-request (request-id uint))
    (map-get? withdrawal-requests { request-id: request-id })
)

(define-read-only (get-required-signatures)
    (var-get required-signatures)
)

(define-read-only (check-nft-in-vault (owner principal) (asset-contract principal) (token-id uint))
    (default-to 
        false 
        (map-get? nft-holdings { owner: owner, asset-contract: asset-contract, token-id: token-id })
    )
)