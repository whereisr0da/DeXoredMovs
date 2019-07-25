/**
 * DeXoredMov's - Copyright (c) 2019 - 2020 r0da [r0da@protonmail.ch]
 *
 * This work is licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License.
 * To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-nd/4.0/ or send a letter to
 * Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
 *
 * By using DeXoredMov's, you agree to the above license and its terms.
 *
 *      Attribution - You must give appropriate credit, provide a link to the license and indicate if changes were
 *                    made. You must do so in any reasonable manner, but not in any way that suggests the licensor
 *                    endorses you or your use.
 *
 *   Non-Commercial - You may not use the material (DeXoredMov's) for commercial purposes.
 *
 *   No-Derivatives - If you remix, transform, or build upon the material (Steamless), you may not distribute the
 *                    modified material. You are, however, allowed to submit the modified works back to the original
 *                    Steamless project in attempt to have it added to the original project.
 *
 * You may not apply legal terms or technological measures that legally restrict others
 * from doing anything the license permits.
 *
 * No warranties are given.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using SharpDisasm;

namespace DeXoredMovs
{
    class Program
    {
        static string version = "v0.1";
        static string line = "------------------------------------------------------------------------";

        static bool showDisam = false;
        static bool showOldXor = false;
        static bool hideNop = false;

        static string input = "";
        static string output = "";

        /// <summary>
        /// Entrypoiny
        /// </summary>
        /// <param name="args">arguments</param>
        static void Main(string[] args)
        {
            Console.WriteLine("DeXoredMov's " + version + " by r0da\r\n");

            if (args.Length > 4)
                error("Bad arguments count");

            if((args[0].ToLower() != "-d" && args.Length == 4) ||
                (args[0].ToLower() != "-h" && args.Length == 1))
                error("Bad arguments");

            if (args[0].ToLower() == "-h")
                usages();
            else if (args[0].ToLower() == "-d")
            {
                if (args.Length != 4)
                    error("Bad arguments count");

                showDisam = true;

                int dislayValue = 0;

                try
                {
                    dislayValue = int.Parse(args[1]);
                }
                catch
                {
                    error("Invalid display options");
                }

                if(dislayValue > 2)
                    error("Invalid display options");

                showOldXor = dislayValue >= 1;
                hideNop = dislayValue == 2;

                if (File.Exists(args[2]))
                    error("File exist : " + args[2]);
                output = args[2];

                if (!File.Exists(args[3]))
                    error("File not found : " + args[3]);
                input = args[3];

                disam();
            }
            else
            {
                if (args.Length != 2)
                    error("Bad arguments count");

                if (File.Exists(args[0]))
                    error("File exist : " + args[0]);
                output = args[0];

                if (!File.Exists(args[1]))
                    error("File not found : " + args[1]);
                input = args[1];

                disam();
            }
        }

        /// <summary>
        /// Print errors
        /// </summary>
        /// <param name="str">error message</param>
        static void error(string str)
        {
            Console.Write("Error : "+str+"\r\n");

            Environment.Exit(1);
        }
        
        /// <summary>
        /// Print usages
        /// </summary>
        static void usages() {

            Console.Write("usages : [options] [output] [input]\r\n" +
                "         -d 0 : show disassembly of the code\r\n" +
                "            1 : show old xor before deobfuscation\r\n" +
                "            2 : show old xor before deobfuscation without nops\r\n" +
                "         -h : show usages\r\n");

            Environment.Exit(0);
        }

        /// <summary>
        /// Main disassembly function
        /// </summary>
        static void disam()
        {
            Console.WriteLine("[+] Processing " + new FileInfo(input).Name);

            if (showDisam)
                Console.WriteLine(line);

            int resolved = 0;

            byte[] opcodeBuffer = new byte[1];

            try
            {
                opcodeBuffer = File.ReadAllBytes(input);
            }
            catch
            {
                error("Fail to read input file");
            }

            List<byte> newOpcodeBuffer = new List<byte>();

            // Config disam options
            Disassembler.Translator.IncludeAddress = true;
            Disassembler.Translator.IncludeBinary = true;

            // Create the disam
            Disassembler disasm = new Disassembler(opcodeBuffer, ArchitectureMode.x86_32, 0, true);

            Instruction[] instructions = disasm.Disassemble().ToArray<Instruction>();

            int instructionsCount = instructions.Length;

            // Loop through all instructions
            for (int i = 0; i < instructionsCount; i++)
            {
                // Get current instruction
                Instruction instruction = instructions[i];

                // Except last instruction
                if (i == instructionsCount - 1)
                {
                    printInstruction(instruction);

                    // Add instruction bytes to section
                    addArrayToList<byte>(newOpcodeBuffer, instruction.Bytes);

                    break;
                }

                Instruction instructionAfter = instructions[i + 1];

                // If opcode is XOR
                if (instruction.Mnemonic == SharpDisasm.Udis86.ud_mnemonic_code.UD_Ixor)
                {
                    Operand[] operands = instruction.Operands;

                    // If instruction don't have registers
                    if (operands == null || operands.Length != 2 || instructionAfter.Operands.Length != 2)
                    {
                        printInstruction(instruction);

                        // Add instruction bytes to section
                        addArrayToList<byte>(newOpcodeBuffer, instruction.Bytes);

                        continue;
                    }

                    // If the current instruction is a nop of a register and 
                    // the instruction after xor a value in this register
                    //
                    // Like :
                    //          xor reg1, reg1
                    //          xor reg1, SOMETHING
                    //
                    if (operands[0].Base == operands[1].Base && instructionAfter.Operands[0].Base == operands[0].Base)
                    {
                        if (showDisam)
                        {
                            if (showOldXor)
                            {
                                Console.ForegroundColor = ConsoleColor.Red;

                                Console.WriteLine(instruction.ToString());
                                Console.WriteLine(instructionAfter.ToString());
                            }

                            Console.ForegroundColor = ConsoleColor.Green;
                        }

                        List<byte> newBuffer = new List<byte>();

                        // Get the current xor reg1, SOMETHING
                        byte[] movInstruction = instructionAfter.Bytes;

                        // TODO : handle more cases

                        // Create a mov instruction from the xor 
                        movInstruction[0] = 0x8b; // MOV r16/32 r/m16/32

                        // Add nop to save the length
                        foreach (byte item in instruction.Bytes)
                        {
                            newBuffer.Add(0x90); // NOP
                        }

                        // Add mov instruction bytes to buffer
                        addArrayToList<byte>(newBuffer, movInstruction);

                        // Display new mov instruction
                        if (showDisam)
                        {
                            // Create a new disassembler about this mov
                            Disassembler newDis = new Disassembler(newBuffer.ToArray(), ArchitectureMode.x86_32, 0, true);

                            foreach (Instruction item in newDis.Disassemble())
                            {
                                if (item.Mnemonic == SharpDisasm.Udis86.ud_mnemonic_code.UD_Inop && hideNop)
                                    continue;

                                Console.WriteLine(item.ToString());
                            }
                        }

                        // Add mov instruction bytes to section
                        addArrayToList<byte>(newOpcodeBuffer, newBuffer.ToArray());

                        resolved++;

                        // escape the next instruction
                        // TODO : make something more smart
                        i += 1;

                        continue;
                    }
                    else
                    {
                        printInstruction(instruction);

                        // Add instruction bytes to section
                        addArrayToList<byte>(newOpcodeBuffer, instruction.Bytes);

                        continue;
                    }
                }
                else
                {
                    printInstruction(instruction);

                    // Add instruction bytes to section
                    addArrayToList<byte>(newOpcodeBuffer, instruction.Bytes);
                }
            }

            // Just a simple check to debug
            if(newOpcodeBuffer.Count != opcodeBuffer.Length)
                Console.WriteLine("[-] The length of the output is not the same as the input :(");

            if (showDisam)
                Console.WriteLine(line);

            if (resolved == 0)
            {
                Console.WriteLine("[-] Nothing seems to be obfuscated");
            }
            else
            {
                Console.WriteLine("[+] " + resolved + " obfuscated xor cleaned !");

                Console.WriteLine("[+] Write the deobfuscated output to " + new FileInfo(output).Name);

                try
                {
                    File.WriteAllBytes(output, newOpcodeBuffer.ToArray());
                }
                catch
                {
                    error("Fail to write the output");
                }
            }

            Console.WriteLine("[+] Done");
        }

        /// <summary>
        /// Print instruction
        /// </summary>
        /// <param name="i">the instruction</param>
        static void printInstruction(Instruction i)
        {
            if (showDisam)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(i.ToString());
            }
        }

        /// <summary>
        /// Add an array to a list
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="list"></param>
        /// <param name="array"></param>
        static void addArrayToList<T>(List<T> list, T[] array)
        {
            for (int i = 0; i < array.Length; i++)
            {
                list.Add(array[i]);
            }
        }
    }
}
