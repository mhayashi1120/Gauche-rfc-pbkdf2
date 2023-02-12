;;;
;;; gauche_rfc_pbkdf2
;;;

(define-module rfc.pbkdf2
  (use util.match)
  (use gauche.uvector)
  (export
   compute-pbkdf2))
(select-module rfc.pbkdf2)

;;;
;;; # API
;;;

;; ##
;; - PASSWORD : <string> | <u8vector> TODO
;; - ITER : <integer> Count of iteration
;; - LEN : <integer>
;; - :PRF : (PASSWORD:<u8vector> INPUT:<u8vector>) -> <u8vector>
;; - :salt : <u8vector>
;; -> <u8vector>
(define (compute-pbkdf2 password iter len :key (PRF #f) (salt #f))
  (let ([pass (match password
                [(? string?)
                 (string->u8vector password)]
                [(? u8vector?)
                 password]
                [else
                 (error "Not a supported password")])])
    ;; TODO #xffffffff
    ))


(autoload rfc.hmac hmac-digest)

;; ##
;; -> TODO -> <u8vector>
(define (generate-hmac hasher)
  (^ [pass input]
    ;; TODO
    (hmac-digest :hasher hasher)))