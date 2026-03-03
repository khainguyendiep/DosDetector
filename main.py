import asyncio

HOST = '0.0.0.0'
PORT = 514
class syslog_Protocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        print('UDP server is ready')
    def datagram_received(self, data, addr):
        print(data.decode())
        #add more filter here

stop_event = asyncio.Event()
async def main():
    print('Initing monitor...')
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
            syslog_Protocol,
            local_addr=(HOST, PORT)
    )
    try:
        await stop_event.wait()
    finally:
        transport.close()

asyncio.run(main())
