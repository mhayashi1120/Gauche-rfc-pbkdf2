;;;
;;; Test gauche_rfc_pbkdf2
;;;

(use gauche.test)

(test-start "gauche_rfc_pbkdf2")
(use gauche_rfc_pbkdf2)
(test-module 'gauche_rfc_pbkdf2)

;; The following is a dummy test code.
;; Replace it for your tests.
(test* "test-gauche_rfc_pbkdf2" "gauche_rfc_pbkdf2 is working"
       (test-gauche_rfc_pbkdf2))

;; If you don't want `gosh' to exit with nonzero status even if
;; the test fails, pass #f to :exit-on-failure.
(test-end :exit-on-failure #t)
