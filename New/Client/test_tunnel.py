from Tunnel import Tunnel


def main():
    t = Tunnel()
    t.create("VPNcore")
    while True:
        try:
            msg = t.receive()
            print(msg)
        except KeyboardInterrupt:
            break

    t.close()

main()