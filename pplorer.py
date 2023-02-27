from __future__ import print_function
import idaapi
import idc
import idautils
from netnode import Netnode
import sark
import ida_funcs
from functools import wraps, partial
import struct
import sys

PYTHON3 = sys.version_info.major == 3
if PYTHON3:
    import pickle

    def iterkeys(dct):
        return iter(dct.keys())

    def iteritems(dct):
        return iter(dct.items())
else:
    import cPickle as pickle

    iterkeys = dict.iterkeys
    iteritems = dict.iteritems

NETNODE = "$ pplorer"

class PickleNetNode(Netnode):
    @staticmethod
    def _encode(data):
        return pickle.dumps(data)

    @staticmethod
    def _decode(data):
        return pickle.loads(data)

    @staticmethod
    def cached(cache_key):
        """Decorator for returning cached values from self.cache[cache_key] for method with no arguments"""
        def decorator(method):
            @wraps(method)
            def wrapper(self):
                if hasattr(self, 'log'):
                    log = self.log.info
                else:
                    log = print

                cached_val = self.cache.get(cache_key)
                if cached_val is not None:
                    log("Using cached value for %s" % cache_key)
                    return cached_val
                log("No cached value for %s, generating..." % cache_key)
                result = method(self)
                self.cache[cache_key] = result
                log("Value for %s generated" % cache_key)
                return result
            return wrapper
        return decorator


class PplAnalyzer(object):

    def __init__(self, cache=None):
        self.ppl_dispatch = sark.Function(self.find_ppl_dispatch())
        self.ppl_table = []
        self.ppl_to_func_dict = {}  # link ppl func to a ppl gate call
        self.func_to_ppl_dict = {}  # link ppl gate call to an actual ppl func behind it
        self.analysis_done = False

    def find_ppl_dispatch(self):
        relevant_string = "ppl_dispatch: failed due to bad arguments/state"
        all_strings = idautils.Strings()
        for ida_string in all_strings:
            if relevant_string in str(ida_string):
                l = sark.Line(ida_string.ea)
                for dref in l.drefs_to:
                    dref_line = sark.Line(dref)
                    if dref_line.insn.operands[0].text == "X0":
                        if dref_line.prev.insn.mnem == "B":
                            # this is ppl exit and not what we need
                            continue
                        else:
                            try:
                                func = sark.Function(dref_line.ea)
                            except sark.exceptions.SarkNoFunction as e:
                                func = None
                                mark_line = dref_line
                                for i in range(50):
                                    mark_line = mark_line.prev
                                    if("CMP             X15," in mark_line.disasm):
                                        ida_funcs.add_func(mark_line.ea)
                                        func = sark.Function(dref_line.ea)
                                        break
                                if func is None:
                                    raise Exception("Failed to detect ppl dispatch, requires new start to find")
                            return func.ea
        return None

    def find_ppl_table(self):
        for line in self.ppl_dispatch.lines:
            if "ADRL            X9," in line.disasm:
                return line.insn.operands[1].value
        return None
    
    def find_ppl_table_size(self):
        for line in self.ppl_dispatch.lines:
            value = line.insn.operands[1].value
            if "CMP             X15," in line.disasm and value > 3:
                # the > 3 is to prevent false positives
                return value
        return None

    def get_ppl_table_by_order(self):
        entry_size = 8
        size = self.find_ppl_table_size()
        ppl_table = self.find_ppl_table()
        table = []
        for i in range(size):
            entry = ppl_table + i * entry_size
            line = sark.Line(entry)
            if all(x == 0 for x in line.bytes): # there are some empty entries.
                table.append(0)
            else:
                table.append(struct.unpack("<Q", line.bytes)[0])
        self.ppl_table = table

    def find_all_ppl_calls(self, ppl_dispatch):
        dispatch_wrapper = next(ppl_dispatch.crefs_to)
        line = sark.Line(dispatch_wrapper)
        while "PACIBSP" not in line.disasm:
            """
            We are backtracking the code to find the start to the func.
            We can't use sark.Function on the line because IDA can't identify the PPL gate as a func.
            """
            line = line.prev
        all_calls = list(line.crefs_to)
        return all_calls

    def mark_all_ppl_calls(self):

        def edit_comment(comment, wanted, delete):
            if comment is None:
                comment = ""
            if not delete and wanted not in comment:
                comment = comment.rstrip()
                if comment:
                    comment += '\n'
                comment += wanted
            elif delete and wanted in comment:
                parts = comment.split(wanted)
                comment = '\n'.join((x.rstrip() for x in parts))
            return comment

        for ppl_gate_call_ea in self.find_all_ppl_calls(self.ppl_dispatch):
            line = sark.Line(ppl_gate_call_ea)
            func_selector = line.prev.insn.operands[1].value
            if func_selector < len(self.ppl_table):
                actual_call = self.ppl_table[func_selector]
                comment = idc.get_cmt(ppl_gate_call_ea, True)
                new_comment = edit_comment(comment, "has xref to PPL", delete=False)
                idc.set_cmt(line.ea, new_comment, True)
                self.func_to_ppl_dict[ppl_gate_call_ea] = actual_call
                if actual_call in self.ppl_to_func_dict.keys():
                    self.ppl_to_func_dict[actual_call].append(ppl_gate_call_ea)
                else:
                    self.ppl_to_func_dict[actual_call] = [ppl_gate_call_ea]
            else:
                idaapi.warning(f"Tried to get bad index from ppl table. Index: {func_selector} PPL table len: {len(self.ppl_table)}\n")

    def analyze(self):
        self.get_ppl_table_by_order()
        self.mark_all_ppl_calls()
        self.analysis_done = True

    def can_xref_from_gate_ea(self, ea):
        if ea in self.func_to_ppl_dict.keys():
            return ea

    def can_xref_from_ppl_ea(self, ea):
        if ea in self.ppl_to_func_dict.keys():
            return ea


class PplorerPlugin(idaapi.plugin_t, idaapi.UI_Hooks):
    plugin_initialized = False
    flags = idaapi.PLUGIN_MOD | idaapi.PLUGIN_HIDE
    comment = "find xrefs for ppl gates"
    help = ""
    wanted_name = "Pplorer"
    wanted_hotkey = ""

    class MenuBase(idaapi.action_handler_t):
        label = None
        shortcut = None
        tooltip = None
        icon = -1

        def __init__(self, plugin):
            self.plugin = plugin
            self.name = self.plugin.wanted_name + ':' + self.__class__.__name__
            self.register()

        def register(self):
            return idaapi.register_action(idaapi.action_desc_t(
                self.name,  # Name. Acts as an ID. Must be unique.
                self.label,  # Label. That's what users see.
                self,  # Handler. Called when activated, and for updating
                self.shortcut,  # shortcut,
                self.tooltip,  # tooltip
                self.icon  # icon
            ))

        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.__name__)

        def activate(self, ctx):
            # dummy method
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

        def path(self):
            return "Edit/Plugins/" + self.plugin.wanted_name + "/" + self.label

        def get_name(self):
            return self.name

    class AnalyzeMenu(MenuBase):
        label = 'Analyze IDB...'

        def activate(self, ctx):
            self.plugin.analyze()
            return 1

    class JumpXrefMenu(MenuBase):
        label = 'Jump to PPL XREFs...'
        shortcut = 'Ctrl+Shift+X'
        icon = 151

        def activate(self, ctx):
            self.plugin.choose_window_here()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE if self.plugin.can_find_xrefs_here() else idaapi.AST_DISABLE

    def __init__(self):
        self.analysis_done = False
        self.ppl_analyzer = None
        self.ui_hook = False
        self.analyze_menu = None
        self.jump_xref_menu = None

    def init(self):
        """plugin_t init() function"""
        super(PplorerPlugin, self).__init__()

        typename = idaapi.get_file_type_name().lower()
        if 'arm64e' not in typename:
            print('%s: IDB deemed unsuitable (not an ARM64e binary). Skipping...' % self.wanted_name)
            return idaapi.PLUGIN_SKIP

        if not PplorerPlugin.plugin_initialized:
            self.analyze_menu = self.AnalyzeMenu(self)
            self.jump_xref_menu = self.JumpXrefMenu(self)

            self.ui_hook = True
            self.hook()
            print('%s: IDB deemed suitable. Initializing...' % self.wanted_name)

        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        """plugin_t run() implementation"""
        return

    def term(self):
        """plugin_t term() implementation"""
        if self.ui_hook:
            self.unhook()
            self.ui_hook = False
        return

    def ready_to_run(self):
        """UI_Hooks function.
        Attaches actions to plugin in main menu.
        """

        idaapi.attach_action_to_menu(self.analyze_menu.path(), self.analyze_menu.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(self.jump_xref_menu.path(), self.jump_xref_menu.get_name(), idaapi.SETMENU_APP)
        PplorerPlugin.plugin_initialized = True
        self.analyze(only_cached=True)

    def finish_populating_widget_popup(self, widget, popup_handle):
        """UI_Hooks function
        Attaches the Find Xref action to the dissasembly right click menu.
        """
        if not self.analysis_done:
            return
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM and self.can_find_xrefs_here():
            idaapi.attach_action_to_popup(widget, popup_handle, "-", None, idaapi.SETMENU_FIRST)
            idaapi.attach_action_to_popup(widget, popup_handle, self.jump_xref_menu.get_name(), None,
                                          idaapi.SETMENU_FIRST)

    def analyze(self, only_cached=False):
        cache = PickleNetNode(NETNODE)
        # cache.kill()

        if only_cached:
            if not cache.get('analysis_done', False):
                return
            print('%s: this IDB had been previously analyzed, loading from cache' % self.wanted_name)
        elif self.analysis_done:
            answer = idc.ask_yn(idaapi.ASKBTN_NO, "HIDECANCEL\nRe-analyze the IDB?")
            if answer != idaapi.ASKBTN_YES:
                return
            cache.kill()
            self.analysis_done = False

        should_hide_wait = False
        if not cache.get('analysis_done', False):
            should_hide_wait = True
            idaapi.show_wait_box("HIDECANCEL\n%s analyzing..." % self.wanted_name)

        # not catching exceptions, just want to call the finally block to hide the wait_box
        try:
            self.ppl_analyzer = PplAnalyzer(cache)

            self.ppl_analyzer.analyze()
            if len(self.ppl_analyzer.ppl_table) == 0:
                idaapi.warning(('%s\nUnable to find ppl functions.\n') % self.wanted_name)
                return

            cache['analysis_done'] = True
            self.analysis_done = True
        finally:
            if should_hide_wait:
                idaapi.hide_wait_box()
            if not self.analysis_done:
                cache.kill()

    def choose_ppl_gate_to_func(self, ea):
        ppl_func = self.ppl_analyzer.func_to_ppl_dict[ea]
        if ppl_func == 0:
            return None
        return int(hex(ppl_func), 16)

    def choose_xref_to_ppl_func(self, ea):
        xrefs = self.ppl_analyzer.ppl_to_func_dict[ea]
        if not xrefs:
            return None

        candidates = [[idc.get_func_off_str(addr), "0x%016x" % addr]
                      for addr in xrefs]

        title = 'PPL xrefs to 0x%016X' % ea
        chooser = FuncXrefChooser(title, candidates)
        chosen = chooser.show()

        if chosen is None:
            return None
        return int(chosen[1], 16)

    def pick_choose_func_for_ea(self, ea):
        ref_addr = self.ppl_analyzer.can_xref_from_gate_ea(ea)
        if ref_addr:
            return partial(self.choose_ppl_gate_to_func, ref_addr)

        ref_addr = self.ppl_analyzer.can_xref_from_ppl_ea(ea)
        if ref_addr:
            return partial(self.choose_xref_to_ppl_func, ref_addr)

        return None

    def choose_by_ea(self, ea):
        choose_func = self.pick_choose_func_for_ea(ea)
        if choose_func is None:
            return

        addr = choose_func()
        if addr is not None:
            idc.jumpto(addr)

    def choose_window_here(self):
        if not self.analysis_done:
            return
        self.choose_by_ea(idc.here())

    def can_find_xrefs_here(self):
        if not self.analysis_done:
            return False
        return self.pick_choose_func_for_ea(idc.here()) is not None


class _Choose(idaapi.Choose):
    # Fix Choose.UI_Hooks_Trampoline to work with modal dialogs
    class UI_Hooks_Trampoline(idaapi.Choose.UI_Hooks_Trampoline):
        def populating_widget_popup(self, form, popup_handle):
            chooser = self.v()
            if hasattr(chooser, "OnPopup") and \
                    callable(getattr(chooser, "OnPopup")):
                chooser.OnPopup(form, popup_handle)

    class chooser_handler_t(idaapi.action_handler_t):
        def __init__(self, handler):
            idaapi.action_handler_t.__init__(self)
            self.handler = handler

        def activate(self, ctx):
            self.handler()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_FOR_WIDGET \
                if idaapi.is_chooser_widget(ctx.widget_type) \
                else idaapi.AST_DISABLE_FOR_WIDGET

    def __init__(self, title, items, columns):
        idaapi.Choose.__init__(
            self,
            title,
            columns,
            flags=idaapi.Choose.CH_RESTORE)

        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def show(self):
        selected = self.Show(modal=True)
        if selected < 0:
            return None
        return self.items[selected]


class FuncXrefChooser(_Choose):
    def __init__(self, title, items):
        _Choose.__init__(
            self,
            title,
            items,
            [["Address", 30 | idaapi.Choose.CHCOL_PLAIN], ["Address (Hex)", 20 | idaapi.Choose.CHCOL_HEX]])


def PLUGIN_ENTRY():
    return PplorerPlugin()
