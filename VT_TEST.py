import os
import time

import vt

if __name__ == "__main__":
    print('test')

    directory = '/home/infobeyond/VirusShare/ELF_Linux_i386_x64_86'



    for filename in os.listdir(directory):
        fullname = os.path.join(directory, filename)
        client = vt.Client("cf1fa7147c58038ef9615c5fbc4a2e4496193aef858af6fa9351632c21b1bdbb")

        #file = '/home/infobeyond/VirusShare/VirusShare_PE'

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