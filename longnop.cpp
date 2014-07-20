/*
 * IDA Long-NOP Extension
 *
 * 2010-11-21
 * (c) kongo <fredrik@z80.se>
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

static ea_t ea;

#define segrg specval_shorts.high  // IBM PC expects the segment address
                                   // to be here
#define aux_short       0x0020  // short (byte) displacement used
#define aux_basess      0x0200  // SS based instruction

#define R_cl  9
#define R_ss  18
#define R_ds  19

enum nec_insn_type_t
{
  x86_Long_NOP = CUSTOM_CMD_ITYPE,
};

//----------------------------------------------------------------------
static int get_dataseg(int defseg)
{
  if(defseg == R_ss)
    cmd.auxpref |= aux_basess;

  return defseg;
}

static void process_rm(op_t &x, uchar postbyte)
{
  int Mod = (postbyte >> 6) & 3;
  x.reg = postbyte & 7;

  if(Mod == 3)               // register
    {
      if(x.dtyp == dt_byte)
	x.reg += 8;
      
      x.type = o_reg;
    }
  else                          // memory
    {
      if(Mod == 0 && x.reg == 5)
	{
	  x.type = o_mem;
	  x.offb = uchar(ea-cmd.ea);
	  x.addr = get_long(ea); ea+=4;
	  x.segrg = get_dataseg(R_ds);
	}
      else
	{
	  x.type = o_phrase;      // See reg for phrase
	  x.addr = 0;
	  x.segrg = get_dataseg((x.phrase == 2 || x.phrase == 3 || x.phrase == 6) ? R_ss : R_ds);
                              // [bp+si],[bp+di],[bp] by SS
	  if(Mod != 0)
	    {
	      x.type = o_displ;     // i.e. phrase + offset
	      x.offb = uchar(ea-cmd.ea);

	      if(x.reg == 4)
		{
		  ea++; // SIB byte.
		}

	      if(Mod == 1)
		{
		  x.addr = char(get_byte(ea++));
		  cmd.auxpref |= aux_short;
		}
	      else
		{
		  x.addr = get_long(ea); ea+=4;
		}
	    }
	}
    }
}

int ana(void)
{
  int code = get_byte(ea++);

  if(code == 0x66)
    code = get_byte(ea++);

  if(code == 0x90)
    {
      cmd.itype = x86_Long_NOP;
      return ea - cmd.ea;
    }

  if(code == 0x2E)
    code = get_byte(ea++);

  if(code != 0x0F)
    return 0;

  code = get_byte(ea++);
  switch ( code )
  {
    case 0x1F:
      cmd.itype = x86_Long_NOP;
      {
        uchar postbyte = get_byte(ea++);
        process_rm(cmd.Op1, postbyte);
        return ea - cmd.ea;
      }

    default:
      return 0;
  }
}

const char *get_insn_mnem(void)
{
  if(cmd.itype == x86_Long_NOP)
    return "nop";

  return "lolwut";
}

static int idaapi dirty_extension_callback(void * /*user_data*/, int event_id, va_list va)
{
  switch(event_id)
    {
    case processor_t::custom_ana:
      {
        ea = cmd.ea;
        int length = ana();
        if(length)
	  {
	    cmd.size = length;
	    return length+1;
	  }
      }
      break;
      
    case processor_t::custom_mnem:
      if(cmd.itype >= CUSTOM_CMD_ITYPE)
	{
	  char *buf   = va_arg(va, char *);
	  size_t size = va_arg(va, size_t);
	  qstrncpy(buf, get_insn_mnem(), size);
	  return 2;
	}
      break;
    }
  
  return 0;
}

static bool hooked = false;
static netnode nec_node;
static const char node_name[] = "$ x86 Long NOP extension parameters";

int idaapi init(void)
{
  if(ph.id != PLFM_386)
    return PLUGIN_SKIP;

  nec_node.create(node_name);
  hooked = nec_node.altval(0);

  if(hooked)
    {
      hook_to_notification_point(HT_IDP, dirty_extension_callback, NULL);
      msg("x86 Long NOP extension is enabled\n");
      return PLUGIN_KEEP;
    }

  return PLUGIN_OK;
}

void idaapi term(void)
{
  unhook_from_notification_point(HT_IDP, dirty_extension_callback);
}

void idaapi run(int /*arg*/)
{
  if(hooked)
    unhook_from_notification_point(HT_IDP, dirty_extension_callback);
  else
    hook_to_notification_point(HT_IDP, dirty_extension_callback, NULL);

  hooked = !hooked;
  nec_node.create(node_name);
  nec_node.altset(0, hooked);

  info("AUTOHIDE NONE\n"
       "x86 Long NOP extension is now %s", hooked ? "enabled" : "disabled");
}

char comment[] = "x86 Long NOP extension";

char help[] =
  "This module adds support for multi-byte NOPs in x86 binaries.";

char wanted_name[] = "x86 Long NOP";

char wanted_hotkey[] = "";

__declspec(dllexport) plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC,
  init,
  term,
  run,
  comment,
  help,
  wanted_name,
  wanted_hotkey
};
