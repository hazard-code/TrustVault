;; TrustVault - A secure multi-signature vault with conditional withdrawals
;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-SIGNATURE (err u101))
(define-constant ERR-CONDITION-NOT-MET (err u102))
(define-constant ERR-ALREADY-INITIALIZED (err u103))
(define-constant ERR-NOT-INITIALIZED (err u104))
(define-constant ERR-INSUFFICIENT-BALANCE (err u105))

;; Data variables
(define-data-var contract-owner principal tx-sender)
(define-data-var required-signatures uint u2)
(define-data-var vault-initialized bool false)

;; Maps
(define-map authorized-signers principal bool)
(define-map vault-balances principal uint)
(define-map withdrawal-requests 
    { request-id: uint }
    { 
        amount: uint,
        beneficiary: principal,
        signatures: (list 20 principal),
        condition-time: uint,
        executed: bool
    }
)

;; Counter for withdrawal requests
(define-data-var request-counter uint u0)

;; Public functions
(define-public (initialize (signers (list 5 principal)) (sig-threshold uint))
    (begin
        (asserts! (not (var-get vault-initialized)) ERR-ALREADY-INITIALIZED)
        (asserts! (> sig-threshold u0) ERR-INVALID-SIGNATURE)
        (asserts! (<= sig-threshold (len signers)) ERR-INVALID-SIGNATURE)
        
        ;; Initialize authorized signers
        (map add-authorized-signer signers)
        (var-set required-signatures sig-threshold)
        (var-set vault-initialized true)
        (ok true)
    )
)

(define-public (deposit (amount uint))
    (begin
        (asserts! (var-get vault-initialized) ERR-NOT-INITIALIZED)
        (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
        (map-set vault-balances tx-sender 
            (+ (default-to u0 (map-get? vault-balances tx-sender)) amount))
        (ok true)
    )
)

(define-public (create-withdrawal-request 
    (amount uint) 
    (beneficiary principal)
    (condition-time uint))
    (let
        ((request-id (var-get request-counter)))
        (asserts! (var-get vault-initialized) ERR-NOT-INITIALIZED)
        (asserts! 
            (>= (default-to u0 (map-get? vault-balances tx-sender)) amount)
            ERR-INSUFFICIENT-BALANCE)
        
        (map-set withdrawal-requests
            { request-id: request-id }
            {
                amount: amount,
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

(define-public (execute-withdrawal (request-id uint))
    (let
        ((request (unwrap! (map-get? withdrawal-requests { request-id: request-id }) ERR-INVALID-SIGNATURE)))
        
        (asserts! (var-get vault-initialized) ERR-NOT-INITIALIZED)
        (asserts! (not (get executed request)) ERR-INVALID-SIGNATURE)
        (asserts! (>= block-height (get condition-time request)) ERR-CONDITION-NOT-MET)
        (asserts! 
            (>= (len (get signatures request)) (var-get required-signatures))
            ERR-INVALID-SIGNATURE)
        
        ;; Update balances and execute transfer
        (try! (as-contract 
            (stx-transfer? 
                (get amount request)
                tx-sender
                (get beneficiary request))))
        
        ;; Mark request as executed
        (map-set withdrawal-requests
            { request-id: request-id }
            (merge request { executed: true })
        )
        (ok true)
    )
)

;; Private functions
(define-private (is-authorized-signer (signer principal))
    (default-to false (map-get? authorized-signers signer))
)

(define-private (add-authorized-signer (signer principal))
    (map-set authorized-signers signer true)
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