# frozen_string_literal: true

module Linzer
  module RFC9421
    module Examples
      class << self
        def test_request_data
          {
            http: {
              "method" => "POST",
              "host"   => "example.com",
              "path"   => "/foo"
            },
            headers: {
              "host"           => "example.com",
              "date"           => "Tue, 20 Apr 2021 02:07:55 GMT",
              "content-type"   => "application/json",
              "content-digest" => "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
              "content-length" => "18"
            },
            body: '{"hello": "world"}'
          }
        end

        def test_response_data
          {
            http: {
              "status" => 200
            },
            headers: {
              "date"           => "Tue, 20 Apr 2021 02:07:56 GMT",
              "content-type"   => "application/json",
              "content-digest" => "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
              "content-length" => 23
            },
            body: '{"message": "good dog"}'
          }
        end

        def test_key_rsa
          <<~EOS
            -----BEGIN RSA PRIVATE KEY-----
            MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
            BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
            JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
            jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
            lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
            SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
            vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
            CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
            +m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
            yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
            Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
            YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
            cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
            DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
            mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
            qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
            B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
            9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
            f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
            81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
            /2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
            IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
            qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
            WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
            EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
            -----END RSA PRIVATE KEY-----
          EOS
        end

        def test_key_rsa_pub
          <<~EOS
            -----BEGIN RSA PUBLIC KEY-----
            MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
            WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
            MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
            kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
            uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
            PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
            -----END RSA PUBLIC KEY-----
          EOS
        end

        def test_key_rsa_pss
          <<~EOS
            -----BEGIN PRIVATE KEY-----
            MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
            P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
            3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
            FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
            AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
            9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
            c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
            pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
            aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
            XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
            HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
            2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
            RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
            DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
            vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
            rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
            4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
            FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
            OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
            NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
            NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
            3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
            t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
            dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
            S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
            rOjr9w349JooGXhOxbu8nOxX
            -----END PRIVATE KEY-----
          EOS
        end

        def test_key_rsa_pss_pub
          <<~EOS
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
            +QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
            oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
            gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
            Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
            aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
            2wIDAQAB
            -----END PUBLIC KEY-----
          EOS
        end

        def test_shared_secret
          "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
        end

        def test_key_ecc_p256_pub
          <<~EOS
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
            w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
            -----END PUBLIC KEY-----
          EOS
        end

        def test_key_ecc_p256
          <<~EOS
            -----BEGIN EC PRIVATE KEY-----
            MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
            AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
            4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
            -----END EC PRIVATE KEY-----
          EOS
        end

        def test_key_ed25519_pub
          <<~EOS
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
            -----END PUBLIC KEY-----
          EOS
        end

        def test_key_ed25519
          <<~EOS
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
            -----END PRIVATE KEY-----
          EOS
        end

        # B.1.4. Example Ed25519 Test Key
        def test_key_ed25519_jwk_format
          {
            "kty" => "OKP",
            "crv" => "Ed25519",
            "kid" => "test-key-ed25519",
            "d"   => "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
            "x"   => "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
          }
        end

        # Pinned ML-DSA-44 (FIPS 204) test key pair, generated once with
        # OpenSSL 3.5.6 and fixed here for reproducible tests. ML-DSA
        # signing is randomized, so (unlike RSA/Ed25519 fixtures above)
        # this key pair is only used to assert round-trip behavior, never
        # a fixed expected signature value.
        def test_key_ml_dsa_44
          <<~EOS
            -----BEGIN PRIVATE KEY-----
            MIIKPgIBADALBglghkgBZQMEAxEEggoqMIIKJgQgTt8dJQaIVGuaXIQkcy4D7LK2
            l1NnyxJ5J09zGpPAf8sEggoAyLKqjEmFoli+CCcP8WxjQOOqU0yb4p9pvv3v3Ean
            IKny3k90t9+OE5ZqnoureN8qQ+flcYqPZy1sFqPm2FlgzSV/rMdilRFoAOt8iuo7
            blbOcZmUFHHbuaY42NIbp+aB7K3Q+NrlyRB+f6GARg02WqPaP4CYHfKXLnwHo2O2
            HdoZxE0RwCGbuAggRmDiECUjBw1JtklAKAkjlAgYkE0ZMzCKQjLCSAyElAwYiGAQ
            BSEcRU1RMGnZsEAIOXFKwgGMKGpjOHEkMGbJNiqDuCxbpFAEQoQJEiTEwJBKmGgk
            E4XUpA3jkEhSoGgiKHKYxoEbwQ0LsBEZSGYJFkhkmEHAgIVIME0aQwBTCJBZmIFE
            xkwSIDEbAS6bljFCKGXgFGBZJG4MkElEOCnSQFJjEEQRw42AxhEgo4hYmEAEJVBc
            xAzZtDGTiCnKFpAQtU2CxGAjFyZaAIVRJJHQpDGUMgERBGJChmgJFI1hGE4SFUyR
            IAkUGG6QRi0BACUEoUUKgUWBuA0ZI01MmIkIqJGSOBAJBYwBCYogBgVZNAYQiGDc
            NBIIIoWUACKJME0UBBBUAiwRxEzJNkSgJgkKxoCRlIUTNlEihoAMBi7ShFBLAIEb
            ABBQJk1JyITANHBaAkDJoIyTpGFZMA7aQmWKNnBARopClIzjtEnZtCUgQjBBRkma
            MHDhRCqKJpIbuGwEFY0gKREBMgUTpmwACETMMDAaI0AAsiFJMiQgkyAaoiHIAIIc
            uSHaOCZcMBEkQpChtiQaRWyShG2hCAiYECAhti3YNg2aEA4RwWDCAEnUBEwIIyaj
            IJGIki0aFlGQhg0ZQIkJk5BBBEwauWSLFG4BMwGTME6CSGYUGQYCkgGEoiQgkUWh
            Qo7cGCTBNgmSMJIBplGLJIWBFHITJE4RlzEAuEmkOBJUAIJTEkyEBmJiRoIZRkZg
            EkkbiTEJsm2IGCxgomyMIIAMlXAMBg3ROBGixomRBHEJgiGZRkYEgRHZIi4EIoDi
            AkpcJAjEJkAkmYzkKE2TKGFQQHKESGQjti0RsQ3BKIIQJ4nMIgkKgiWKFFFchkSR
            KCVcGBEhIYQJM05SlG0CRW0QSXGaIECRGFDQliXiMi4SNygiBFGBmFBRBCUhkBAj
            IRJENgbgoAGSwAlTFCnQlHGIIiIbQQyBqAHcMmocqAEbwiCEEIWJNAqTBmjBRJAQ
            ySWfJL/U3tDhFdLRULFNJouoyLafjt9n/1x/Blvi2St2dhJ5joMVnJg2+7tKe7kB
            rF5vOn3hCvlN7y/gpVvsd/VZWEIcCA0MBvlnAy9KQPPjRI1UpMA+kSxO4aY1ETdP
            ynu0yQlGWxbW/Eo2IdFtf3vEqlJnyIUSBrr9EHxmO5/4cOUqB3+AO5cPNMhqrJ4r
            OagIOrTE5oneBpMNktB5+D3k0FXPzMmMgycilAAhl9f/fX9xGrZ3+6RS2CzKGT+k
            YCz7+4KqtRIxAZ1h6E3N8OaXs/Q+295Qz5KVZc4qSBca2tbULRSDUh6GhxcoKLiv
            oRMNRCziLpAizqypgfEXXL4ukz51cry1oVB5K9s0/Z4B0+nKPxaMhnbULRaoEAEN
            WaSon/5tIV+p3Q+HQSy2QugD8HbQWvJpxP9VFsLc3rldO47+D1mzd+iCWwVbT0Gr
            5FBpXdKrDPmRwS1lLXPyi6g/kR/rizHL6ne4sTmM9fLlsexbBCUvVQZb4CROVH7D
            zTfIAvpXvs6tORq/vDitw6pktMJxLWH3jT2eKvcxYsxZiiQrlhCs1n2Kl7a+283l
            kXNzKDCmjwjgAKqbsPxie9vbsxFOtuxMWmMbMfBhAkwPMw++vicI4XqhVAcfqQ1I
            MTX8em/2cqyDIYU7KfktUU3QlwAmtSkakTUzoUBJPH1+9FMYbfptO7aMZIAwtLu0
            g3yqokLWN45gqQzHmlRuuceM0GlFcOcoQxX+oBQayf09BaNGeZTSJ26itl22YE0n
            hF/Wxlw5Ayhge8lANwoBLB85SQcnHU3E/o9Ql6gfjI43i5gOsz+QZyzwr3Tw3DDR
            Wqrm6H8R18M/ptDRLOTGiPXnLIqCmmgLf/dkSfy6zaVtOUo5eCgVJnDlZ2dRX3Xl
            3RrkoYbGxklKWwTGkLaC0jC71qjOxmvlliMeEWcULtaZUvKsv6urpj5s0xFX7sm2
            uQ8zgXex2H3vfBWAAm4hIyqx4hRufhGBQlkN20iXsjJLlKiUKX4x2BbNuXNr9p73
            bHpoQ9HVA2EvCuKwl+QfIfsCZ+OHEwj2JrIAqm5qqb6Le51k8h296R4DBqTeoKMy
            soFtLhViO9c90IT13gOC731i3pWOZ9hz1N+nUjRiBL/7vZvzEEeiAmsXWCW7xrB2
            95yWCNZWxQqFmkacfhZoEgrmPYi3g51ZEFPJ8P9kXvygHVOlwrKHsBws3mpkHWDu
            kj+7vw/oyi87u5rZgH9HPtFrnQTA66lckOypZceCV3ykg95jhLuta1WLWQudBOQw
            Ql4mDWIWbPSTwJJOwjLBl8GxP+UhxTvhBudz3txYK7kxjdMdIm9hR4/vRc+zao5+
            3A9/Dh9u1B8OBthwC/GDVMwoDh3yfgniPvPITjda5tnEpY53tJxI5UzdnZ5EtPhD
            /znvALBb0U0UYbK6q4gNZ23vw3RGek3tOJkFquvWPYBr5n0QqVbkEgtQodsPnMcP
            09SyVLr8o+USrhGhUpYpm501XnLRZ+jTMJqYv7E4uA+S4APlf82iw65+QFROA+SS
            R7CMUCc4+Yo/GcNZI+Itn/vz3SV06c9BF8lzmVhhfT4FVEOmUpzmON2+cCZ2zRgt
            8f1vn9HwrxV2tIHtKRbEgvuR7S2YkooMAj5NPs6w0SPkGGJtBX/owITuxeDBPU6+
            Og8x63MDMYNeTV4ZARDdtqTphP4TYsyqu6fspcDZkAT6UC5I7zzXpW2ed56uUfnC
            cAkBWUEzxLkKlAUsIqZmpiHI2N32qGKPUq5ILovo8zd/g28x0uhwoIGQNWaT6bUV
            SM/XSzct/LJtrOaQf7db+5uRbE5p3wzDWlQ/NVhb4Wx79BHSDy6DazHAxT9W/E5G
            TYswxtqch0Xtac+HI4hwfTwliJ0sERP0nxsqeqbqA2FZClGAIfcCI2dmGvehiPXg
            5qNQT6PScZC1JUKR0R6DbOe0RlQmbOue37bBcNHg2VILIwucD8kJT9dvcYvEBMPm
            CVhvgVwecY7SxGcNjJemFeYf4/2kD306fh3HqLUOvrBa22bvZ8Dvbw+llu+ofhWn
            aQSNMCCQCkmnnEWwgdGO6U+r75NNwhAAn5DoZnMegr1dk/EwvncWI8DsUDyBe6O6
            dWtOWHi95CPPfFKIDy+WQ6Ni50YAwxYbpsrc04pfOLSKs7mQIoc55QW/NJIqT9bQ
            LuAHxRq3Y9cxoxtjFUAESWR06rRL350qRkl1XCu7KOsAqQ==
            -----END PRIVATE KEY-----
          EOS
        end

        def test_key_ml_dsa_44_pub
          <<~EOS
            -----BEGIN PUBLIC KEY-----
            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
            -----END PUBLIC KEY-----
          EOS
        end

        # ML-DSA-44 test vector from the C2SP httpsig-pq specification
        # (Post-Quantum Algorithms for HTTP Message Signatures), v0.2.0.
        # https://github.com/C2SP/C2SP/blob/httpsig-pq/v0.2.0/httpsig-pq.md
        #
        # The public key and signature are raw FIPS 204 encodings (not PEM),
        # per the spec. Verified independently against OpenSSL 3.5.6 while
        # implementing this feature.
        def test_ml_dsa_44_vector
          {
            keyid: "test-key-mldsa44",
            label: "sig1",
            created: 1783368000,
            request: {
              method: "GET",
              path: "/foo",
              query: "param=Value&Pet=dog",
              host: "example.com",
              date: "Mon, 06 Jul 2026 20:00:00 GMT"
            },
            components: %w[@method @target-uri host date],
            signature_input:
              'sig1=("@method" "@target-uri" "host" "date")' \
              ';created=1783368000;keyid="test-key-mldsa44";alg="ml-dsa-44"',
            public_key_b64:
              "guWbbXQe/Y1a83/qIeU8MjIrRseICPuOyWzoGXk27Fia2lpk2uPxbEfh/iEmvY1z" \
              "/LTtxSBFZS8zbgV04qa038ZokwE+QoBcISX0H4F9hEY3Oxg8SRtzrek0E+mBOc6R" \
              "4ilBje5vodImgSMTMSXKuDz2PWqvrLY20AfLmMkLXZqVERYcW+S7iKyTP53cvte" \
              "nYwealt3MGcZxLKRAMnCGBY3pRfj1xn6czY6OuMYNuJaW1rAeL2BeVpNA+XBA+H" \
              "UHS1yTYOGw93ddFe9lw0RDex7Pw+tht/n31gggrR4D0kmE8L88Q5c2qWuQtxk9+" \
              "cmHTm3u1WuG/vCRiubTA3DmY0pK1fO1etarscNRnZ06q5UfTgSQOMqR/PLXtqT9" \
              "cZiN8GWQvum15uVuxXCubB4r7T3nz2ijyBPQfo+Ywd10QxI8dpGpsBd9SEslLo+" \
              "esyFDt7+9t4c702PNC0121oI18PriNlKxjxshQljNnrXSZ4eCvhHrY5Le8B/mTw" \
              "sb/LYPbBvktCecvkRxboTjhyq2anblDt5Hp55gn+0YRWUz7myuDjBD/+a2riHzO" \
              "XCoLOtGvsfVTLAwLPYj/AIBbdVFrGq9MKldtcgiqTWhG6JWD/dxFrfUT4YIf2yW" \
              "O9AbhkgkgPynKmV82sLda4L3JaABwSXVAB1vzDmxfQ17orBFxX2pK23G5EmrG8I" \
              "x/1O9NJ35LSxkZhUmNs+4zm9GRaChPbw04q//Gc9CPiE3xvv/BrRms5mIiRl7zT" \
              "8o2mgNs/APM45mJrKClmYRQllKVwnKBj+njZkDv1CG2WeBv01COmic4P4EEraSm" \
              "KO8I5sJ98gpTiA9jeBuvloLYdAInPyZui01GyQO4P3OETyAVqggBGIvajxWuio7" \
              "eL+4XZmkX3AMb5XrfWtlfYCKUzhodcv7NM6M4LizEh0KZ8qSHsnVZxqwb5J9hb4" \
              "oiR5/N7sgxjjtiBsbg/vJ1UmBZZR6hPjnLbLDTZ6PUMjeQNdoYGL0Cv4ESloaEt" \
              "c4vhW/Aa2roIyoAM/kimrHYztNknxZK3nLQ9PXVp9Np1okp4VPUkOfHvy6Bk2WP" \
              "Qd8vdwrfE3xOPGrkhzdmlcsVEp3rIAW4s4Hem2A99CFSkbPePEEPG4uB3sVl73X" \
              "+sr8+X7jFkiiy686eV73zQTrqL4OnrYJIkaZr6zLXHccvm1txmftmtS3WH3Ny0h" \
              "GVjwxnu1femv2++2pZpZr67//WBksxPOG4xk6AA7xrHEAjRFA0b0g6AC3+WuZma" \
              "NCNMd8YdibEt/WHKg7uGWYetMf45cWxPxZmNl+jddlf1btTAfYZ+eXla3Tx/pg5" \
              "fU2EWTXyTOVIRdRwAOpZHG7jFYCxRE2SWFFM2lwjLxzso69uABhM1zraUxo6TfO" \
              "alw1x7S1NkTowesaJPlTMmr43N5hdbRyDD6qmcCSNNjDICvK/fv3ijSY0lueglt" \
              "1Jf7O1fi9/s0CNGf8E/pQohdb/pzGhSlJRo73hC/wTmLEjFukAYNdNeJO8Fxge7" \
              "j6rLHIOu22q8lK0DSsWqXXeFYt5mKmdTOFHN6soJQ7Uk43HgwoMreCn6xJQhl87" \
              "CZu4SUzr5XztrsOV/YF5u5IYY8cDneoZW+0ldE+/8bvI8gi352YmfL9ZY5TacDe" \
              "xbl0S+hGbR7IPHh6av0N+odj2uBNt4Cjb3Mt3aYwQi2Yh9vD+CaGcz5AO67GAf7" \
              "pIpS8naBrzQeNjdOYLxu6VcXT4zLO9Gu1Uv+RvkLPaalcAQ==",
            signature_b64:
              "xMPE4JdLqAZ69uTOeLp4kAqExJpuY1JBqXtOslHrYcuAZ4VWxCNvDbqZPE6WuJRR" \
              "IHc0f7AVjYEKmKe1YfNgWnilnzXaKfLo3O1jJsOMMYwtfnpHOHKY6JwvJbG+prQr" \
              "Ly1B4+GQa87nF43XbyAZx5/Hm86AfSep/yXYfctzAAFF2CPKwONhTv3JxKNu1ke3" \
              "J5FKqWUiDBQyCT0/MRdEEE+EfUNuM3z2yPm8/XHRrPXGhdKfprb0c6OzcUTPiAq1" \
              "0x6gsFviSfgdfOA7yYVgjnou/wOCDCoZmSIrShxQbYtfVk3jnyuK0LQR+vSMrAz" \
              "v9cCuQAcFFXK0ckf2p1nASr4BvJHWM98H6qTrm1vytPDbhnoaMLBQyxxGJhEMIW" \
              "04yR8Td9LwXFY9Jt6p6HQqITSy2s9lOXmDk9UWQXJ+TK220apBOHqHvAst6fyOf" \
              "2HJFyn4NkthzcbCFFSaGx7PtJvNid7NQYi811e3jEbiqwva+cKAy7CaIyq5ufwy" \
              "s5072YG0mUz7Cc7h2jCRWQLHvEQwbi/ZLUY92lEaqBO0eSRQfJ3CkpvxMY4nY/U" \
              "+Dtw5IHzPbK4olqaktMuiUYbC2QDvFm/LZ5UUFSYTdGNJtmDPMZZNtzYatgn1m1" \
              "aTmtHTpT1d64DIFG7WCqAQwIzgfZRUMAFlHcQKq4jOkEzX4nBtezw5vrqilu3MC" \
              "5XNsjC+cEVtZsnDj6MShmFkQEkn4lgpEy5bVxX8Ku8aucMwKWxCQ0gQFGsKGdoN" \
              "C9iFPw3EsdWqpgvkhXtav2dFxqQJTE4boN0g7DVW1GrrTeIdkfX9o4lPLfW5XWi" \
              "7Q0Sywt37U7DG/hHGdlz3vC/uLNv8O6keycUFfnIU7culqs0OBCj4RiijDk+5ic" \
              "rKzAmr/ufOb0O5fdw0rfaztaANHyBpgPzENAl4qRa3SecWErZbS7fAyjbc1fYwP" \
              "xisp0Htc4MTNomaCoy9JihoFpHkV4q6zaLMQPg9yQYvEjfEBcGL3IcfdXgfG2jg" \
              "z0/+ggq68iz/99RMFA2znvm87T/fNMAXtvXBIHROX2/RfZ/U+X4MgB+kZdptWWz" \
              "WoTcPT2M/JZB25/rR2zmsSI/wFVbKiTFA3sobQUJlUo/96DGKlPsPqR0hz423lE" \
              "Yn5v40tu1qfINcGPms7lHXn7JhtCahFndZv7WsONV2p4Oi8fD+07sA3g4cfq15U" \
              "kt1JYIWze71GxI4XCx4f6ExFhSLVqx32hadk9q0vAMWZHw5k5oHnqVBKx988fmr" \
              "NTNGuYqAQsKmsKDNRqduBQ+EKsg8wj4cRjFEYAQiw67OFgE4r20dsF9GuFJeN01" \
              "CNLL+SDtnB0O/6cVdxfi3rlfrkfuyFD5oqE9JgFp8tOnJCQT7c/YoFvm+1pMsB9" \
              "Vn5SirdApdO1gA5qwrCaUq6xAsz+xqNZeOD5q5tp89BnsyQ/m5Got8aLHXNI5RK" \
              "g0i2H9sK5yj3nm70ZZjHo4V4Fmbd6ANphOPb4BBtYQm/xraGA4+2G+GqIG9aqTa" \
              "+xqWEUnn5xWgO8DUybJbAqGAlcrVpyQVTJe7TOERAfhA45rZxxvwfcxu1kMX4QQ" \
              "HTtqiz5MHL4I8AcpZhMtlzDCKXwpG8vaMSIv+RdkDZDOyS3/zumvdMoy/4+kHUq" \
              "wnCy9NMatHTdWu/pD3KDiFndHw9oxoD6uzDWm6hwJNnxbM/u/7lRZMJkPaMR9xy" \
              "d4t2ctWGmEtcJBfT7cclxMRdzdIO8Qz/ggshWg3bbJrWslL6wFSOkmZkscSWTJt" \
              "UMkWSl2a0df92UvdvJpV6SHhy9NWlHq6hn04vKo55/BbjhFNRyOZIJx/3WnUQIV" \
              "bhApDBHrf3DpzfcvnlkyQZvxtCqdPzN5nHDVZ50+01nye/b+WsUH56ga+ALzNmP" \
              "S2iHZAirlBQA3td4r+MvFyW6wAdYWEQYsF4LMtNyhURYB+oEPEesLu7Op61sZty" \
              "DUT2aXknqtgsjBJU+D1lfey27x82BjbZ/1/6S0GKDc4+8fXF8+AnntdaQbWbAcd" \
              "QXTs//EmRFvCJMa0+rKiULt8zQz6g53Bum8M12YfUKRDTCHD0o8HjzTL4Hyhhq8" \
              "yIzV4b9J5Q7tXqTsUsaSq6Jti0drlwSGM9ZADaEbC+EpkSBh9rVMqSwZBmmnumU" \
              "c6UjDtiKXLs8l2h47HX+hNWxt1uZSAO9SWzsJ3Bw9cTa2Hwi8mEEXAWk56GUJQ5" \
              "1tWNbxsApLvCOC/jui+KfqfG9FXrveOAhM0fUCYJaztXEOyIPAlY7MPD9oIhY1w" \
              "PfRf6cVNVfdMWxtIjiuLyl35E2EpKU5aL/qp0HiZ6CkciFJvt3Q+E6+r6FMzM2Q" \
              "DG9iMpwA3YvFA2ZBs4Hgcv2lNvE31/LT78zrtBaqesAFvDwJ5rx9vWfI9jP01ch" \
              "m9its8Rp77lnQM95eJp6Y4+RzJKF5gjYqyke9CAErkmyaBZE/cd8vkNZFUvu5db" \
              "toqUZPFIHG7TBodCimgKpWxJZOuKUKujviSsDdp5V/aDvJiUFfEas5Pzl4E8FHQ" \
              "nM+ucjEhKyqHdye9faMVYat9f5UfHLK52mKmWog8wa7JjMtDfVG6GF/ZWx8s8qD" \
              "SZltNqMsb1H6nVxRaGrZjt+OzTSyCkQV4oG90I93zMkYUQWLm9Zp5QIt/6Lp+vN" \
              "3bh+QHWqiyIozEJsd/vcYJBcm49nxJhAPs1EgXr4esryJKFVp4fDo3kg7lDYPY1" \
              "nL9EJP9XYZex6V5oqKh6ozwDuwfVj0A+2nmqsW2LBUUvwEX95aVXI+X2QMSQJMI" \
              "ajMwUHtVwBqTHU2VEgYVzmIsc00HoaBAGMCPb0nA0468h+FO7MPlZvADg08xmNM" \
              "xoPQEVCu67p62iePUlrhuHxBPlko2Q1r/+coZVG8Yc6BB3DovIweezsdeJmut9R" \
              "rDIMbigewyoQ67+SC2zN0rLe9vpgqM9+REuk6kkdJW2YCMI1PbrexSAlIaTjz+R" \
              "A4+lYIrFXYqFXD6ie/hLIF71J+XTaGZtVQy0jdFOZ5kX16oatMr1QYh1ESe5sLj" \
              "iPlC3o8+RYZze6qBfvMi9B+FICpMO+UqUOlrnhBVKuxYTZc/IsFXrr2TlvKKRy4" \
              "fAzZGM0jOsXkAjMkCVYzMs8QQFCU4PlNfYGNrpLO4xcjM1tjp6+0rMjU9XnF4gI" \
              "uXprTH1+Pq+xc4PkpMcXJ1d4GKjqnE1dfh5PT7KC9HaGx+naOorK75AAAAAAAAA" \
              "AAAABUmOkY="
          }
        end
      end
    end
  end
end
