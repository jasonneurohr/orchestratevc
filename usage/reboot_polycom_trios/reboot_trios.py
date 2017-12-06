import orchestratevc

with open("iplist.txt") as trio_list:
    for address in trio_list:
        address = address.strip()
        trio = orchestratevc.PolycomTrio(address, "Polycom", "pass@word1")
        print("Address {}, result: ".format(address) + trio.safe_restart())
