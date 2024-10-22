from aktest_se import Se, SDKConfiguration
from edgegrid import EdgeRc, EdgeGridAuth
import argparse
from pathlib import Path
import httpx
import logging

logger = logging.getLogger(__name__)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--edgerc", metavar='', type=str, help="location of .edgerc file", default="~/.edgerc")
    parser.add_argument("--section", metavar='', type=str, help="section of token inside .edgerc file", default='default')
    parser.add_argument("-c", "--contract", metavar='', type=str, help="contractId without ctr_ prefix")
    parser.add_argument("-a", "--accountkey", metavar='', type=str, help="account switch key")
    parser.add_argument("--id", metavar='', type=str, help="enrollment id")
    args = parser.parse_args()

    if args.edgerc is None:
        edgerc = EdgeRc(f'{str(Path.home())}/.edgerc')
    else:
        edgerc = EdgeRc(f'{str(Path(args.edgerc))}')

    section = args.section if args.section else 'default'
    auth = EdgeGridAuth.from_edgerc(edgerc, section)
    host = edgerc.get(section, 'host')

    server_url=f"https://{host}/cps/v2"
    sdk_config = SDKConfiguration(server_url, async_client=None, debug_logger=logger)
    s = Se(sdk_config, server_url, client=httpx.Client(auth=auth))
    res = s.enrollments.get_enrollments(contract_id=args.contract, account_switch_key=args.accountkey, server_url=server_url)


    for r in res.enrollments:
        try:
            print(r.csr.sans)
        except AttributeError as e:
            print(e)

    res = s.enrollments.get_enrollment(enrollment_id=args.id, account_switch_key=args.accountkey)
    print()
    print(res.csr)


    '''
    client = httpx.Client(auth=auth)
    resp = client.get("https://akab-y2lbugj6ikgeep6u-o4o6mtx2qbo4wror.luna.akamaiapis.net/cps/v2/enrollments",
                      headers={'accept': "application/vnd.akamai.cps.enrollments.v11+json"},
                      params={"contractId": "W-QZ88G8",
                              "accountSwitchKey": "F-AC-5015077"
                             })
    print()
    print(resp.status_code)
    '''


