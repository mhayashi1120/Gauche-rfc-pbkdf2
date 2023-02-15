;;;
;;; Test gauche_rfc_pbkdf2
;;;

(use compat.chibi-test)
(use gauche.test)

(test-start "rfc.pbkdf2")

(use rfc.pbkdf2)
(test-module 'rfc.pbkdf2)

(debug-print-width #f)

(use gauche.uvector)
(use rfc.sha1)
(use gauche.process)

(define (->hex u8)
  (with-output-to-string
    (^[]
      (u8vector-map (^b (format #t "~2,'0X" b) b) u8))))

(define (hex->u8vector h)
  (let1 hex (regexp-replace-all* h #/[ \n]/ "")
    (with-input-from-string hex
      (^[]
        (let loop ([l ()])
          (let1 b (read-string 2)
            (cond
             [(eof-object? b)
              (list->u8vector (reverse! l))]
             [else
              (loop (cons (string->number b 16) l))])))))))

(define (pbkdf2-sha1 pass iter size salt)
  (compute-pbkdf2-hmac pass iter size :salt salt :hasher 'sha1))

;; -> [KEY:<string> IV:{<string> | #f}]
(define (openssl-key&iv pass iter size :key (salt #f) (hash-algorithm 'sha256))
  (and-let* ([args (cond-list
                    [salt @ (list  "-S" salt)]
                    [(not salt) @ (list "-nosalt")]
                    [#t (ecase size
                          [(16)
                           "-aes-128-ctr"]
                          [(24)
                           "-aes-192-ctr"]
                          [(32)
                           "-aes-256-ctr"])]
                    )]
             [out (process-output->string
                   `(openssl enc
                             -md ,hash-algorithm
                             -e -pbkdf2
                             -iter ,iter
                             -pass ,(format "pass:~a" pass)
                             -P ,@args))]
             [m-key (#/key *=([0-9a-f]+)/i out)]
             [key (m-key 1)])
    (if-let1 m-iv (#/iv *=([0-9a-f]+)/i out)
      (values key (m-iv 1))
      (values key #f))))

(define (openssl-key . args)
  (values-ref (apply openssl-key&iv args) 0))


;; (dolist (iter '(100000))
;;   (let ([pass "hogehoge1"]
;;         [size 32]
;;         [algo 'md5])
;;     #?= (equal? (openssl-key pass iter size :hash-algorithm algo)
;;                 (->hex (compute-pbkdf2-hmac
;;                         pass iter size
;;                         :hasher algo)))))

;; (exit 0)
(chibi-test
 (test-group "RFC 3962 (B.  Sample Test Vectors)"
   (test-group "password with salt 1"
     (test
      (hex->u8vector "cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15")
      (pbkdf2-sha1 "password" 1 16  (string->u8vector "ATHENA.MIT.EDUraeburn")))
     (test
      (hex->u8vector "cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15 0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37")
      (pbkdf2-sha1 "password" 1 32  (string->u8vector "ATHENA.MIT.EDUraeburn"))))

   (test-group "password with salt 2"
     (test
      (hex->u8vector "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d")
      (pbkdf2-sha1 "password" 2 16  (string->u8vector "ATHENA.MIT.EDUraeburn")))
     (test
      (hex->u8vector "01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86")
      (pbkdf2-sha1 "password" 2 32  (string->u8vector "ATHENA.MIT.EDUraeburn"))))

   (test-group "password with salt 3"
     (test
      (hex->u8vector "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b")
      (pbkdf2-sha1 "password" 1200 16  (string->u8vector "ATHENA.MIT.EDUraeburn")))
     (test
      (hex->u8vector "5c 08 eb 61 fd f7 1e 4e 4e c3 cf 6b a1 f5 51 2b a7 e5 2d db c5 e5 14 2f 70 8a 31 e2 e6 2b 1e 13")
      (pbkdf2-sha1 "password" 1200 32  (string->u8vector "ATHENA.MIT.EDUraeburn"))))

   (test-group "password with salt 4"
     (test
      (hex->u8vector "d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49")
      (pbkdf2-sha1 "password" 5 16  (hex->u8vector "1234567878563412")))
     (test
      (hex->u8vector "d1 da a7 86 15 f2 87 e6 a1 c8 b1 20 d7 06 2a 49 3f 98 d2 03 e6 be 49 a6 ad f4 fa 57 4b 6e 64 ee")
      (pbkdf2-sha1 "password" 5 32  (hex->u8vector "1234567878563412"))))

   (test-group "Pass phrase = (64 characters)"
     (test
      (hex->u8vector "13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9")
      (pbkdf2-sha1 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" 1200 16  (string->u8vector "pass phrase equals block size")))
     (test
      (hex->u8vector "13 9c 30 c0 96 6b c3 2b a5 5f db f2 12 53 0a c9 c5 ec 59 f1 a4 52 f5 cc 9a d9 40 fe a0 59 8e d1")
      (pbkdf2-sha1 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" 1200 32  (string->u8vector "pass phrase equals block size"))))

   (test-group "Pass phrase = (65 characters)"
     (test
      (hex->u8vector "9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61")
      (pbkdf2-sha1 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" 1200 16 (string->u8vector "pass phrase exceeds block size")))
     (test
      (hex->u8vector "9c ca d6 d4 68 77 0c d5 1b 10 e6 a6 87 21 be 61 1a 8b 4d 28 26 01 db 3b 36 be 92 46 91 5e c8 2a")
      (pbkdf2-sha1 "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" 1200 32 (string->u8vector "pass phrase exceeds block size"))))

   (test-log "Testing ~s" (with-output-to-string (^[] (write-bytevector #u8(#xf0 #x9d #x84 #x9e)))))

   (test-group "Pass phrase = g-clef (0xf09d849e) (musical-symbol UTF-8 sequence)"
     (test
      (hex->u8vector "6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39")
      (pbkdf2-sha1 (hex->u8vector "f09d849e") 50 16 (string->u8vector "EXAMPLE.COMpianist")))
     (test
      (hex->u8vector "6b 9c f2 6d 45 45 5a 43 a5 b8 bb 27 6a 40 3b 39 e7 fe 37 a0 c4 1e 02 c2 81 ff 30 69 e1 e9 4f 52")
      (pbkdf2-sha1 (hex->u8vector "f09d849e") 50 32 (string->u8vector "EXAMPLE.COMpianist"))))
   )

 (test-group "low-level compute-pbkdf2"
   (let ([pass "password0001"])
     (test
      (openssl-key pass 1 32 :hash-algorithm 'sha256)
      (->hex (compute-pbkdf2 pass 1 32)))))

 (test-group "same as openssl command"
   (dolist (pass '("password0001" "qwerty"))
     (test-group (format "Password ~s" pass)
       (dolist (size '(16 24 32))
         (test-group (format "Size ~a" size)
           (dolist (algo '(md5 sha256))
             (test-group (format "Algorithm ~a" algo)
               (dolist (iter '(1 2 3 4 5 100))
                 (test (openssl-key pass iter size :hash-algorithm algo)
                       (->hex (compute-pbkdf2-hmac
                               pass iter size
                               :hasher algo)))

                 (test (openssl-key pass iter size :salt "0102030405060708" :hash-algorithm algo)
                       (->hex (compute-pbkdf2-hmac
                               pass iter size
                               :hasher algo
                               :salt (u8vector 1 2 3 4 5 6 7 8)))))))))))


   (test-group "Large iterations"
     ;; openssl aes-192-ctr -md sha256 -e -pbkdf2 -iter 10000 -pass pass:hogehoge3021 -P -nosalt
     (test "EC863DA2A2EE13A85045053C647474A9DB884942794E629B"
           (->hex (compute-pbkdf2-hmac
                   "hogehoge3021" 10000 24
                   :hasher <sha256>)))

     ;; openssl aes-256-ctr -md sha256 -e -pbkdf2 -iter 10000 -pass pass:qwerty -P -S "0102030405060708"
     (test "517FE483AF63FF8B51946F7B422BEB349F9C7CA7C9B4574914A21A8E44D94501"
           (->hex (compute-pbkdf2-hmac
                   "qwerty" 10000 32
                   :hasher <sha256>
                   :salt (u8vector 1 2 3 4 5 6 7 8))))

     ;; openssl aes-256-ctr -md sha256 -e -pbkdf2 -iter 10000 -pass pass:hogehoge3021 -P -nosalt
     (test "EC863DA2A2EE13A85045053C647474A9DB884942794E629BF3CA71C5C3F511F7"
           (->hex (compute-pbkdf2-hmac
                   "hogehoge3021" 10000 32
                   :hasher <sha256>)))
     )))

(test-end :exit-on-failure #t)
