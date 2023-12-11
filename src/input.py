import argparse
import subprocess

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Lan speed testing')
    parser.add_argument('--ip', type=str, help='IP destination', required=True)
    parser.add_argument('--mode', type=str, choices=['TCP', 'IP'], help='Mode', required=True)
    
    #TCP customization command line argument
    parser.add_argument('--srcport', type=str, help='source port')
    parser.add_argument('--destport', type=str, help='destination port')
    parser.add_argument('--mss', type=int, help='(NOT used, setting this will do nothing, SORRY) MSS size', default=10000)
    parser.add_argument('--variant', choices=['SAW', 'SWF', 'SWCC'], help='TCP Variant', default="SAW")
    parser.add_argument('--packsize', type=int, help='Packet size', default=1460)
    parser.add_argument('--period', type=int, help='Testing period', default=10)
    
    #IP customized command line argument
    parser.add_argument('--packet_size', type=int, help='Packet size', default=50)
    parser.add_argument('--interval', type=float, help='Packet send interval', default=2)
    parser.add_argument('--num_packets', type=int, help='Number of packets', default=10)

    args = parser.parse_args()

    #if the mode is TCP, run tcp executatble
    if args.mode == 'TCP':
        command = ['./LAN_SPEED', str(args.variant), str(args.mss), str(args.packsize),
                   str(args.ip), str(args.srcport), str(args.destport),
                   str(args.period)]
        
    #if the mode is IP, run ip executable
    elif args.mode == 'IP':
        command = ['./PING', "-c", str(args.num_packets), "-i", str(args.interval), "-s", str(args.packet_size), "-ip", str(args.ip)]

    subprocess.run(command)

    # Plotting
    if args.mode == 'TCP':
        #only SWCC variant in tcp has conjection window graph
        if args.variant == 'SWCC':
            plot_command = ['python3', 'plottcp.py']
        else:
            plot_command = ['python3', 'plotTcpWithoutCongestionWindow.py']
    elif args.mode == 'IP':
        plot_command = ['python3', 'plotPing.py']
    
        
    subprocess.run(plot_command)
