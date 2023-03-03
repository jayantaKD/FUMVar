import multiprocessing
import gp
from multiprocessing import Process, Pipe
import time

class multiProcess:
    def test_function(self, child_conn, pop):
            pop.fname = pop.fname + 'test'
            child_conn.send(pop)
            child_conn.close()
            # for i in range(100):
            #     print(pop.fname + ' done - ' + str(i))
            time.sleep(5)
            # for i in range(1000000):
            #     print('twst' + str(i))
            return

    def task(self):
        string = "dsdsdsdsd"
        fbytes = bytes(string, 'utf-8')
        pops = []

        for i in range(50):
            member = gp.Chromosome(fbytes)
            member.fname = str(i)
            pops.append(member)

        parent_conns = []
        child_conns = []
        procs = []
        for i in range(50):
            print(i)
            parent_conn, child_conn = Pipe()
            proc = multiprocessing.Process(target=self.test_function, args=(child_conn, pops[i]))
            procs.append(proc)
            parent_conns.append(parent_conn)
            child_conns.append(child_conn)
            proc.start()
            proc.join()

            # t1 = multiprocessing.Process(target=self.test_function, args=(child_conn, pops[0]))
            # t2 = multiprocessing.Process(target=self.test_function, args=(child_conn1, pops[1]))
        # start_time = time.time()
        # t1.start()
        # t2.start()
        #
        # t1.join()
        # t2.join()

        for i in range(50):
            #procs[i].join()
            pass

        for i in range(50):
            pop = parent_conns[i].recv()
            print(pop.fname)

        # print(t1.is_alive())
        # print(t2.is_alive())

        # pop1 = parent_conn.recv()
        # pop2 = parent_conn1.recv()
        # end_time = time.time() - start_time
        #
        # print(pop1.fname)
        # print(pop2.fname)
        # print(end_time)

        # start_time = time.time()
        # for i in range(1000000):
        #  print('twst' + str(i))
        # end_time = time.time() - start_time
        # print(end_time)

#print(pop2.fname)
# t2.start()

t = multiProcess()
t.task()