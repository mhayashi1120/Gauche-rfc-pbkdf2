;;;
;;; Test gauche_rfc_pbkdf2
;;;

(use gauche.test)

(test-start "rfc.pbkdf2")
(use rfc.pbkdf2)
(test-module 'rfc.pbkdf2)

(test-end :exit-on-failure #t)
