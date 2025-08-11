struct data_t {
   int pid;
   int uid;
   unsigned short l3_proto;
   char command[16];
   char message[12];
   char path[16];
};

struct msg_t {
   char message[12];
};
