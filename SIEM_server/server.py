import socket
import asyncio

SERVER_IP = ''
PORT = 4000
async def handle_clients(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f'{addr} has been connected')

    while True:
        data = await reader.readline()
        if not data:
            print(f'Disconnected with {addr}')
            break
        print(data)
        writer.write('Server captured new log!'.encode())
        await writer.drain()

async def main():
    print('Initing server...')
    print('Complete')
    server = await asyncio.start_server(handle_clients, SERVER_IP, PORT)
    async with server:
        await server.serve_forever()

asyncio.run(main())
