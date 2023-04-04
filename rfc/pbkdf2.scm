;;;
;;; rfc.pbkdf2
;;;

(define-module rfc.pbkdf2
  (use util.digest)
  (use util.match)
  (use gauche.uvector)
  (export
   generate-hmac
   compute-pbkdf2 compute-pbkdf2-hmac))
(select-module rfc.pbkdf2)

;; <u8vector> -> <u8vector> -> <u8vector>
(define (u8xor u1 u2)
  (assume (= (u8vector-length u1) (u8vector-length u2)))
  (u8vector-map logxor u1 u2))

;; - SIZE : <integer>
;; - VALUE : <integer>
;; -> <u8vector>
(define (pack-octet size value)
  (let loop ([v value]
             [i size]
             [r ()])
    (cond
     [(= 0 i)
      (apply u8vector r)]
     [else
      (loop (ash v -8)
            (- i 1)
            (cons (logand #xff v) r))])))

(define (compute-size hasher)
  ;; Get metaclass value
  (slot-ref hasher 'hmac-block-size))

(define (with-input-from-bytes b thunk)
  (let1 op (open-input-bytevector b)
    (unwind-protect
     (with-input-from-port op thunk)
     (close-port op))))

(autoload rfc.md5 <md5>)
(autoload rfc.sha1 <sha1> <sha224> <sha256> <sha384> <sha512>)
(autoload rfc.hmac hmac-digest)
(autoload gauche.vport open-input-bytevector open-output-bytevector get-output-bytevector)

;; -> <message-digest-algorithm>
(define (ensure-hasher hasher)
  (match hasher
    ['sha256 <sha256>]
    ['sha512 <sha512>]
    ['sha224 <sha224>]
    ['sha384 <sha384>]
    ['sha1 <sha1>]
    ['md5 <md5>]
    [(? (^x (subclass? x <message-digest-algorithm>)) clz)
     clz]
    [_
     (error "Not a supported hasher" hasher)]))

;; Heuristic compute octet size of digest generate by <PRF>
;; <PRF> -> <integer>
(define (compute-block-size prf)
  ($ u8vector-length $ prf "" #u8()))

;;;
;;; # API
;;;

;; ## Basic:
;;
;; <PRF>  ::= PASSWORD:<string> -> INPUT:<u8vector> -> <u8vector>
;;
;; ### <PRF>
;;
;; Pseudo Random Function maybe use HMAC algorithm.

;; ## Low level API. Maybe just use [=compute-pbkdf2-hmac]()
;; - PASSWORD : <string> | <u8vector>
;; - ITER : <integer> Count of iteration.
;; - LEN : <integer> Request length of  result.
;; - :prf : <PRF>
;; - :block-size : <integer> To suppress the overhead of the compution,
;;           should assign this value which is length of `prf` generated.
;; - :salt : <u8vector>
;; -> <u8vector>[LEN]
(define (compute-pbkdf2
         password iter len
         :key (prf (generate-hmac <sha256>))
         (block-size (compute-block-size prf))
         (salt #u8()))

  ;; <string>
  (define P (match password
              [(? string?)
               password]
              [(? u8vector?)
               (u8vector->string password)]
              [_
               (error "Not a supported password")]))

  ;; -> <u8vector>
  (define (F* U :optional (i 1))
    (let1 Ux (prf P U)
      (cond
       [(= i iter) Ux]
       [else
        (u8xor Ux (F* Ux (+ i 1)))])))

  ;; -> <list BYTE:<integer>>
  (define (DK request-size :optional (i 1))
    (let* ([U0 (u8vector-append salt (pack-octet 4 i))]
           [T (u8vector->list (F* U0))]
           [size* (- request-size (length T))])
      (cond
       [(<= size* 0)
        (take T request-size)]
       [else
        (append T (DK size* (+ i 1)))])))

  (assume-type iter <integer>)
  (assume (< 0 iter))
  (assume-type len <integer>)
  (assume (< 0 len))
  (assume-type prf <procedure>)
  (assume (= (arity prf) 2))
  (assume-type block-size <integer>)
  (assume (< 0 block-size))
  (assume-type salt <u8vector>)

  (when (< (* #xffffffff block-size) len)
    (error "Invalid length of request" len))

  ($ list->u8vector $ DK len))

;; ## High level api of [=compute-pbkdf2]()
;; - :hasher : {sha256 | sha512 | sha224 | sha384 | sha1 | md5} |
;;      <message-digest-algorithm>
;; -> <u8vector>
(define (compute-pbkdf2-hmac
         password iter len
         :key (hasher 'sha256) (salt #u8()))
  (let1 hasher* (ensure-hasher hasher)
    (compute-pbkdf2 password iter len
                    :prf (generate-hmac hasher*)
                    :block-size (~ hasher*'hmac-block-size)
                    :salt salt)))

;; ## Generate common HMAC procedure.
;; NOTE: rfc2898 doesn't forcibly use HMAC (maybe i think...) but almost
;;    preceeding implementation (e.g. ruby) use just HMAC. i don't enough
;;    know about it.
;; - HASHER : <message-digest-algorithm>
;; -> <PRF>
(define (generate-hmac hasher)
  (^ [pass input]
    (assume-type input <u8vector>)
    (with-input-from-bytes
     input
     (^[]
       ($ string->u8vector
          $ hmac-digest :key pass :hasher hasher)))))
