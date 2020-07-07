import PySimpleGUI as sg
import subprocess as sub
import sys


def main():
    sg.theme('DarkAmber')
    layout = [
        [sg.Text('Acksys telemetry dev tool')],
        [sg.Text('IP address'), sg.InputText(key='_IP_'), sg.Text('Port'), sg.InputText(key='_PORT_')],
        [sg.Button('OK'), sg.Button('Close')],
        [sg.Text()]
    ]

    window = sg.Window('Acksys telemetry dev tool', layout)

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED or event == 'Close':
            break

        if event == 'OK':
            start_client(values['_IP_'], values['_PORT_'], window=window)

    window.close()


def start_client(ip, port, timeout=None, window: sg.Window=None):
    p = sub.Popen('python AckTlvConn.py %s %s' % (ip, port), shell=True, stdout=sub.PIPE, stderr=sub.STDOUT)
    output = ''
    for line in p.stdout:
        line = line.decode(errors='replace' if sys.version_info < (3, 5) else 'backslashreplace').rstrip()
        output += line
        sg.Print(line)
        window.refresh() if window else None
    retval = p.wait(timeout)
    return retval, output


if __name__ == '__main__':
    main()

