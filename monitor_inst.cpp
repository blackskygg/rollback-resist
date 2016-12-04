#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <memory>
#include <utility>

#include <cstdlib>
#include <cstring>
#include <cinttypes>

#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include <ctime>
#include <sys/time.h>

extern "C" {
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
  
#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>
}

using namespace std;

////////////////////////Variable//////////////////////////////////////////
class Variable {
public:
  Variable(addr_t vaddr, size_t size) :
    vaddr(vaddr), size(size), curr_val(size, 0) {};
  void record(vmi_instance_t vmi, addr_t dtb);
  void putback(vmi_instance_t vmi, addr_t dtb);
  
public: //static functions
  static void setup_tss(TSS_CONTEXT *tss_ctx);
  
private:
  addr_t vaddr;
  size_t size;
  string curr_val;
  struct timeval curr_tm;
  vector< pair<struct timeval, string> > history;

  void extend_sha1();

private: //static variables
  static  TSS_CONTEXT *tss_ctx;
  static  PCR_Extend_In pcr_in;
};

TSS_CONTEXT *Variable::tss_ctx = NULL;
PCR_Extend_In Variable::pcr_in;

void Variable::setup_tss(TSS_CONTEXT *tc)
{
  tss_ctx = tc;
  pcr_in.digests.count = 1;
  pcr_in.digests.digests[0].hashAlg = TPM_ALG_SHA1;
}

void Variable::extend_sha1()
{
  TPM_RC rc = 0;
  struct sigaction act, old_act;
  
  memset(&this->pcr_in.digests.digests[0].digest, 0, sizeof(TPMU_HA));
  memcpy(&this->pcr_in.digests.digests[0].digest,
	 &this->curr_tm, sizeof(struct timeval));
  memcpy(&this->pcr_in.digests.digests[0].digest + sizeof(struct timeval),
	 this->curr_val.c_str(),
	 this->curr_val.length());

  // the extend operation should not be interrupted
  act.sa_handler = SIG_IGN;
  act.sa_flags = 0;
  sigaction(SIGHUP,  &act, &old_act);
  sigaction(SIGTERM, &act, &old_act);
  sigaction(SIGINT,  &act, &old_act);
  sigaction(SIGALRM, &act, &old_act);

  rc = TSS_Execute(this->tss_ctx,
		   NULL,
		   (COMMAND_PARAMETERS *) &this->pcr_in,
		   NULL,
		   TPM_CC_PCR_Extend,
		   TPM_RS_PW, NULL, 0,
		   TPM_RH_NULL, NULL, 0);
  
  sigaction(SIGHUP,  &old_act, NULL);
  sigaction(SIGTERM, &old_act, NULL);
  sigaction(SIGINT,  &old_act, NULL);
  sigaction(SIGALRM, &old_act, NULL);

  if (0 != rc) puts("pcr extend error!");
}

void Variable::record(vmi_instance_t vmi, addr_t dtb)
{
  string new_val(size, 0);
  access_context_t ctx;

  //use the dtb(aka. cr3) to read the content in vaddr
  ctx.addr = this->vaddr;
  ctx.dtb = dtb;
  ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
  vmi_read(vmi, &ctx, &new_val[0], this->size);

  if(new_val != curr_val) {
    //record time and new value, and extend sha1
    struct timeval tm;

    gettimeofday(&tm, NULL);
    this->curr_val = new_val;
    this->curr_tm = tm;
    this->history.push_back(make_pair(tm, new_val));
    this->extend_sha1();

#ifdef DEBUG
    //logging
    cout << endl << endl;
    cout << "value: " << this->vaddr <<" = " <<endl;
    for (auto c: this->curr_val) {
      printf("%x ", (unsigned char)c);
    }
    cout<<endl;

    cout << "time: " << asctime(localtime(&tm.tv_sec))
	 << "u_sec: " << tm.tv_usec << endl;
    cout << endl << endl;
#endif //DEBUG
  }

}

void Variable::putback(vmi_instance_t vmi, addr_t dtb)
{
  access_context_t ctx;
	     
  //use the dtb(aka. cr3) to read the content in vaddr
  ctx.addr = this->vaddr;
  ctx.dtb = dtb;
  ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
  vmi_write(vmi, &ctx, &this->history[0].second[0], this->size);
}
////////////////////////Variable//////////////////////////////////////////

////////////////////////WatchPoint//////////////////////////////////////////
class WatchPoint {
public:
  vector<addr_t> vaddrs;
  vector<Variable> vars;

  void watch(vmi_instance_t vmi, addr_t dtb);
  void time_wrap(vmi_instance_t vmi, addr_t dtb);

};

void WatchPoint::watch(vmi_instance_t vmi, addr_t dtb)
{
  cout<<"recording variables"<<endl;
  for (Variable& v: this->vars) {
    v.record(vmi, dtb);
  }
}

void WatchPoint::time_wrap(vmi_instance_t vmi, addr_t dtb)
{
  for (Variable& v: this->vars) {
    v.putback(vmi, dtb);
  }
}

////////////////////////WatchPoint//////////////////////////////////////////

////////////////////////InstMonitor/////////////////////////////////////////
class InstMonitor {
public:
  InstMonitor(const char* vm_name, pid_t pid);
  ~InstMonitor();
  void add_watchpoint(WatchPoint *);
  void start_monitor();
  void stop_monitor();
  void time_wrap();

private:
  set<addr_t> va_list;
  vector<WatchPoint *> watch_points;
  unordered_map<addr_t, uint8_t> va2inst;
  //coz the mapping from vaddr to watchpoint is a many-to-1 mapping,
  //we use pointers to ensure that different addrs are linked to
  //the same watchpoint instance
  unordered_map<addr_t, WatchPoint *> va2wp;
  
  reg_t cr3;
  pid_t pid;
  vmi_instance_t vmi;
  vmi_event_t intr_event;
  vmi_event_t ss_event;
  reg_t last_intr_rip;
  bool interrupted;
  bool intr_enabled;
  bool injected;

  void set_last_intr_rip(reg_t rip);
  reg_t get_last_intr_rip();
  void inject_int3(addr_t vaddr);
  void restore_inst(addr_t vaddr);
  void inject_all();
  void restore_all();

  //callbacks
  static event_response_t intr_callback(vmi_instance_t, vmi_event_t *);
  static event_response_t singlestep_callback(vmi_instance_t, vmi_event_t *);
};

event_response_t InstMonitor::singlestep_callback(vmi_instance_t vmi, vmi_event_t *event)
{
  InstMonitor *mon = (InstMonitor *)event->data;

  mon->inject_int3(mon->get_last_intr_rip());
  vmi_stop_single_step_vcpu(mon->vmi, event, event->vcpu_id);
#ifdef DEBUG
  cout << "stoping  single step" <<endl;
#endif
  
  return 0;
}

event_response_t InstMonitor::intr_callback(vmi_instance_t vmi, vmi_event_t *event)
{
  InstMonitor *mon = (InstMonitor *)event->data;
  reg_t cr3;

  //see if it's not our process that caused this int3, ignore it
  vmi_get_vcpureg(mon->vmi, &cr3, CR3, event->vcpu_id);
  if (cr3 != mon->cr3)  {
    event->interrupt_event.reinject = 1;
    return 0;
  }
  
  //get the vaddr at which the program is trapped
  reg_t rip;
  vmi_get_vcpureg(mon->vmi, &rip, RIP, event->vcpu_id);
  printf("INT 3 happend! RIP: 0x%lx\n", rip);

  //tell the corresponding WatchPoint to record this change
  mon->va2wp[rip]->watch(mon->vmi, cr3);

  //save this rip for further reinjection of int3
  mon->set_last_intr_rip(rip);

  //setup a single step event to put back the INT3 to rip
  SETUP_SINGLESTEP_EVENT(&mon->ss_event, 0, &InstMonitor::singlestep_callback, 1);
  SET_VCPU_SINGLESTEP(mon->ss_event.ss_event, event->vcpu_id);
  mon->ss_event.data = mon;
  vmi_register_event(mon->vmi, &mon->ss_event);

  //restore the original instruction so that the program can continue
  mon->restore_inst(rip);
  event->interrupt_event.reinject = 0;

  return 0;
}

InstMonitor::InstMonitor(const char* vm_name, pid_t pid)
{
  this->vmi = NULL;
  if (vmi_init(&this->vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, vm_name)
      == VMI_FAILURE) {
    cout<<"Failed to init LibVMI library."<<endl;
    throw exception();
  } 

  cout<<"LibVMI init succeeded!"<<endl;
  this->pid = pid;
  cout<<"My pid="<<this->pid<<endl;
  this->cr3 = vmi_pid_to_dtb(this->vmi, this->pid);
  cout<<"My cr3="<<this->cr3<<endl;
}

InstMonitor::~InstMonitor()
{
  if (NULL != this->vmi) {
    if (this->injected)
      this->restore_all();
    vmi_destroy(this->vmi);
  }
}

void InstMonitor::time_wrap()
{
  for (auto wp: this->watch_points)
    wp->time_wrap(this->vmi, this->cr3);
}

void InstMonitor::add_watchpoint(WatchPoint *wp)
{
  uint8_t inst;

  this->watch_points.push_back(wp);
  for (auto vaddr: wp->vaddrs) {
    //add vaddr to vaddr list
    this->va_list.insert(vaddr);

    //if it's a new vaddr, recored the original instruction at vaddr,
    //and map the vaddr to it's corresponding wathpoint,
    // so that when trapped at vaddr, we know who to call
    if (this->va2inst.end() == this->va2inst.find(vaddr)) {
      
      printf("Physical address=0x%lx\n", vmi_translate_uv2p(this->vmi, vaddr, this->pid));
      vmi_read_8_va(this->vmi, vaddr, this->pid, &inst);
      printf("Original content=%d\n", inst);
      this->va2inst[vaddr] = inst;
      
      this->va2wp[vaddr] = wp;
    }
  }
}

void InstMonitor::inject_int3(addr_t vaddr)
{
  uint8_t int3 = 0xcc;
  vmi_write_8_va(this->vmi, vaddr, this->pid, &int3);
  printf("reinjecting int3 at %lx\n", vaddr);
}

void InstMonitor::restore_inst(addr_t vaddr)
{
  uint8_t inst = this->va2inst[vaddr];
  vmi_write_8_va(this->vmi, vaddr, this->pid, &inst);
}

void InstMonitor::inject_all()
{
  if (!this->injected) {
    vmi_pause_vm(this->vmi);
    for (auto va: this->va_list)
      inject_int3(va);
    vmi_resume_vm(this->vmi);

    this->injected = true;
  }
}

void InstMonitor::restore_all()
{
  if (this->injected) {
    vmi_pause_vm(this->vmi);
    for (auto va: this->va_list)
      restore_inst(va);
    vmi_resume_vm(this->vmi);

    this->injected = false;
  }
}


void InstMonitor::set_last_intr_rip(reg_t rip)
{
  this->last_intr_rip = rip;
}

reg_t InstMonitor::get_last_intr_rip()
{
  return this->last_intr_rip;
}

void InstMonitor::start_monitor()
{
  status_t status = VMI_SUCCESS;

  //setup the int3 event
  cout<<" -- Enabling intr-event"<<endl;
  SETUP_INTERRUPT_EVENT(&this->intr_event, 0, &InstMonitor::intr_callback);
  this->intr_event.data = this;
  vmi_register_event(this->vmi, &this->intr_event);

  //inject all int3's
  this->inject_all();
  
  //start monitoring
  this->intr_enabled = false;
  this->interrupted = false;
  while(!this->interrupted) {
    cout << "Listening for events" << endl;
    vmi_events_listen(this->vmi,500);
  }
  cout << "Listener stopped" << endl;
}

void InstMonitor::stop_monitor()
{
  this->interrupted = true;
}
////////////////////////InstMonitor/////////////////////////////////////////


////////////////////////TestCode///////////////////////////////////////////
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
////////////////////////TestCode/////////////////////////////////////////
