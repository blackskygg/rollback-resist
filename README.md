# rollback-resist
Leveraging libvmi and TPM to record variable changes of applications running inside a VM.


# Example
    InstMonitor* inst_mon;
    const addr_t pcrs[] = {0x64fee0, 0x64ff44, 0x64ffa8, 0x65000c,
		          0x650070, 0x6500d4, 0x650138, 0x65019c,
		          0x650200, 0x650264, 0x6502c8, 0x65032c,
		          0x650390, 0x6503f4, 0x650458, 0x6504bc,
		          0x650520, 0x650584, 0x6505e8, 0x65064c,
		          0x6506b0, 0x650714, 0x650778, 0x6507dc};  //sha1 bank of pcrs
    const addr_t pcrextend_addr = 0x42ac33;  //the addr of "retq" within PCRExtend()

    static void close_handler(int sig){
      inst_mon->stop_monitor();
    };

    int main(int argc, char *argv[])
    {
      TSS_CONTEXT *tss_ctx = NULL;
      TPM_RC rc = 0;
      WatchPoint wp;
      struct sigaction act;
      int n_pcrs;
    
      if(argc < 4){
        cerr<<"Usage: interrupt_events_example <name of VM> <pid> <npcrs>" <<endl;
        exit(1);
      }
    
      //setup sig handlers for a clean exit
      act.sa_handler = close_handler;
      act.sa_flags = 0;
      sigemptyset(&act.sa_mask);
      sigaction(SIGHUP,  &act, NULL);
      sigaction(SIGTERM, &act, NULL);
      sigaction(SIGINT,  &act, NULL);
      sigaction(SIGALRM, &act, NULL);
    
      //setup InstMonitor
      try {
        inst_mon = new InstMonitor(argv[1], strtoul(argv[2], NULL, 0));
      } catch(exception e) {
       goto EXIT;
      };

      //Give class Variable a tss context
      if ((rc = TSS_Create(&tss_ctx))) goto EXIT;
      Variable::setup_tss(tss_ctx);
    
      //setup a Watchpoint to watch n_pcr Variables when rip reaches pcrextend_addr
      wp.vaddrs.push_back(pcrextend_addr);
      
      n_pcrs = strtod(argv[3], NULL);
      cout << "testing "<< n_pcrs <<" pcrs" <<endl;
      for (int i = 0; i < n_pcrs; ++i)
        wp.vars.push_back(Variable(pcrs[i], 20));

      //start monitoring wp
      inst_mon->add_watchpoint(&wp);
      inst_mon->start_monitor();

      //cleaning and exiting
     EXIT:
      cout << "exiting..." <<endl;
      TSS_Delete(tss_ctx);
      delete inst_mon;
      return EXIT_SUCCESS;
    }
