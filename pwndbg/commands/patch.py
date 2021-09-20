#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse

import pwndbg.commands
import pwndbg.memory
import pwndbg.memoize

import pwndbg.color.message as message

from pwnlib.asm import asm, disasm


# Keep old patches made so we can revert them
patches = {}


parser = argparse.ArgumentParser(description="Patches given instruction with given code or bytes")
parser.add_argument("address", type=int, help="The address to patch")
parser.add_argument("ins", type=str, help="instruction[s]")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def patch(address, ins):
    new_mem = asm(ins, arch=pwndbg.arch.current)

    old_mem = pwndbg.memory.read(address, len(new_mem))

    patches[address] = (old_mem, new_mem)

    pwndbg.memory.write(address, new_mem)

    pwndbg.memoize.reset()


parser2 = argparse.ArgumentParser(description="Revert patch at given address")
parser2.add_argument("address", type=int, help="Address to revert patch on")
@pwndbg.commands.ArgparsedCommand(parser2)
@pwndbg.commands.OnlyWhenRunning
def patch_revert(address):
    if not patches:
        print(message.info('No patches to revert'))
        return

    if address == -1:
        for addr, (old, _new) in patches.items():
            pwndbg.memory.write(addr, old)
            print(message.info("Reverted patch at %#x" % addr))
        patches.clear()
    else:
        old, _new = patches[address]
        pwndbg.memory.write(address, old)


    pwndbg.memoize.reset()
    
parser3 = argparse.ArgumentParser(description="List all patches")
@pwndbg.commands.ArgparsedCommand(parser3)
@pwndbg.commands.OnlyWhenRunning
def patch_list():
    if not patches:
        print(message.info('No patches to list'))
        return

    print(message.info('Patches:'))
    for addr, (old, new) in patches.items():
        old_insns = disasm(old, arch=pwndbg.arch.current)
        new_insns = disasm(new, arch=pwndbg.arch.current)

        print(
            message.info("Patch at"),
            message.warn("%#x:" % addr),
            message.info("from"),
            message.warn(old_insns.replace('\n', '; ')),
            message.info("to"),
            message.warn(new_insns.replace('\n', '; ')),
        )

