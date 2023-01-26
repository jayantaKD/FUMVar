import os
import time

import vt

from malconv_nn import malconv

def vt_test():
    print('test')

    # directory = '/home/infobeyond/VirusShare/ELF_Linux_i386_x64_86'
    directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_20130711'

    for filename in os.listdir(directory):
        fullname = os.path.join(directory, filename)
        client = vt.Client("cf1fa7147c58038ef9615c5fbc4a2e4496193aef858af6fa9351632c21b1bdbb")

        # file = '/home/infobeyond/VirusShare/VirusShare_PE'

        with open(fullname, "rb") as f:
            analysis = client.scan_file(f)
            print(analysis)

        while True:
            report = client.get_object("/analyses/{}", analysis.id)
            print(report.status)

            if report.status == "completed":
                print(report)
                break
            time.sleep(30)
    client.close()


def malcov_prediction():
    print('test')

    # directory = '/home/infobeyond/VirusShare/ELF_Linux_i386_x64_86'
    directory = '/home/infobeyond/workspace/VirusShare/VirusShare_x86-64_WinEXE_20130711'
    n_network = malconv('./malconv/malconv.h5')
    for filename in os.listdir(directory):
        fullname = os.path.join(directory, filename)
        prediction = n_network.predict(fullname)
        print(prediction)



if __name__ == "__main__":
    print('test')
    #malcov_prediction()
    n_network = malconv('./malconv/malconv.h5')
    prediction = n_network.predict('/home/infobeyond/workspace/VirusShare/VirusShare_PE')
    print(prediction)
