import socket
import asyncio
HOST = 'localhost'
PORT = 514

class InitUDPConnection:
    def connection_made(self, transport):
        self.transport = transport
        print('UDP server get ready')
    def datagram_received(self, data, addr):
        message = data.decode()
        print(message)

stop_event = asyncio.Event()
async def main():
    print('Initing server...')
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
            lambda: InitUDPConnection(),
            local_addr =(HOST, PORT)
    )
    try:
        await stop_event.wait()
    finally:
        transport.close()
asyncio.run(main())
