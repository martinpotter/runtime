// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

.assembly extern System.Console { }

//  Microsoft (R) .NET Framework IL Disassembler.  Version 1.2.2204.0
//  Copyright (C) Microsoft Corporation 1998-2002. All rights reserved.


// This IL was generated from the following C# program on 10/7/02 using csc version
// 8.00.2276 with CLR version 2.x86chk.  This tests functionality which currently compiles
// and passes, but which we know will not be supported in a future version of the compiler.
// This is an attempt to isolate the test coverage from pending changes to csc.
// mwilk. 10/7/02.

// // BEGIN ORIGINAL CODE

//using System;
//
//class Foo<U>
//{
//	public static string Function<T>(U u,T t)
//	{
//		return u.ToString()+t.ToString();
//	}
//		
//}
//
//public class Test
//{
//	public static int counter = 0;
//	public static bool result = true;
//	public static void Eval(bool exp)
//	{
//		counter++;
//		if (!exp)
//		{
//			result = exp;
//			Console.WriteLine("Test Failed at location: " + counter);
//		}
//	
//	}
//	
//	public static int Main()
//	{
//
//		Eval(Foo<int>.Function<int>(1,1).Equals("11"));
//		Eval(Foo<string>.Function<int>("string",1).Equals("string1"));
//		Eval(Foo<int>.Function<string>(1,"string").Equals("1string"));
//		Eval(Foo<string>.Function<string>("string1","string2").Equals("string1string2"));
//		
//		if (result)
//		{
//			Console.WriteLine("Test Passed");
//			return 100;
//		}
//		else
//		{
//			Console.WriteLine("Test Failed");
//			return 1;
//		}
//		
//	}
//}
//
// // END ORIGINAL CODE



// Metadata version: v1.2.2130
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .hash = (F6 74 0E 71 08 12 53 3B 10 F7 F4 D7 0A F1 C6 DF   // .t.q..S;........
           5E 98 AD 4C )                                     // ^..L
  .ver 1:2:3300:0
}
.assembly method014
{

  // --- The following custom attribute is added automatically, do not uncomment -------
  //  .custom instance void [mscorlib]System.Diagnostics.DebuggableAttribute::.ctor(bool,
  //                                                                                bool) = ( 01 00 00 01 00 00 ) 

  .hash algorithm 0x00008004
  .ver 0:0:0:0
}
.module method014.exe
// MVID: {5E79BC95-82C1-4B20-8867-C903C4ECBE7E}
.imagebase 0x00400000
.subsystem 0x00000003
.file alignment 512
.corflags 0x00000001
// Image base: 0x02FC0000

// =============== CLASS MEMBERS DECLARATION ===================

.class private auto ansi beforefieldinit Foo<([mscorlib]System.Object) U>
       extends [mscorlib]System.Object
{
  .method public hidebysig static string 
          Function<([mscorlib]System.Object) T>(!0 u,
                                                !!0 t) cil managed
  {
    // Code size       32 (0x20)
    .maxstack  2
    .locals init (string V_0)
    IL_0000:  ldarg.0
    IL_0001:  box        !0
    IL_0006:  callvirt   instance string [mscorlib]System.Object::ToString()
    IL_000b:  ldarg.1
    IL_000c:  box        !!0
    IL_0011:  callvirt   instance string [mscorlib]System.Object::ToString()
    IL_0016:  call       string [mscorlib]System.String::Concat(string,
                                                                string)
    IL_001b:  stloc.0
    IL_001c:  br.s       IL_001e

    IL_001e:  ldloc.0
    IL_001f:  ret
  } // end of method Foo::Function

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  1
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method Foo::.ctor

} // end of class Foo

.class public auto ansi beforefieldinit Test_method014
       extends [mscorlib]System.Object
{
  .field public static int32 counter
  .field public static bool result
  .method public hidebysig static void  Eval(bool exp) cil managed
  {
    // Code size       47 (0x2f)
    .maxstack  2
    IL_0000:  ldsfld     int32 Test_method014::counter
    IL_0005:  ldc.i4.1
    IL_0006:  add
    IL_0007:  stsfld     int32 Test_method014::counter
    IL_000c:  ldarg.0
    IL_000d:  brtrue.s   IL_002e

    IL_000f:  ldarg.0
    IL_0010:  stsfld     bool Test_method014::result
    IL_0015:  ldstr      "Test Failed at location: "
    IL_001a:  ldsfld     int32 Test_method014::counter
    IL_001f:  box        [mscorlib]System.Int32
    IL_0024:  call       string [mscorlib]System.String::Concat(object,
                                                                object)
    IL_0029:  call       void [System.Console]System.Console::WriteLine(string)
    IL_002e:  ret
  } // end of method Test::Eval

  .method public hidebysig static int32  Main() cil managed
  {
    .entrypoint
    // Code size       142 (0x8e)
    .maxstack  2
    .locals init (int32 V_0)
    IL_0000:  ldc.i4.1
    IL_0001:  ldc.i4.1
    IL_0002:  call       string class Foo<int32>::Function<int32>(!0,
                                                                  !!0)
    IL_0007:  ldstr      "11"
    IL_000c:  callvirt   instance bool [mscorlib]System.String::Equals(string)
    IL_0011:  call       void Test_method014::Eval(bool)
    IL_0016:  ldstr      "string"
    IL_001b:  ldc.i4.1
    IL_001c:  call       string class Foo<string>::Function<int32>(!0,
                                                                   !!0)
    IL_0021:  ldstr      "string1"
    IL_0026:  callvirt   instance bool [mscorlib]System.String::Equals(string)
    IL_002b:  call       void Test_method014::Eval(bool)
    IL_0030:  ldc.i4.1
    IL_0031:  ldstr      "string"
    IL_0036:  call       string class Foo<int32>::Function<string>(!0,
                                                                   !!0)
    IL_003b:  ldstr      "1string"
    IL_0040:  callvirt   instance bool [mscorlib]System.String::Equals(string)
    IL_0045:  call       void Test_method014::Eval(bool)
    IL_004a:  ldstr      "string1"
    IL_004f:  ldstr      "string2"
    IL_0054:  call       string class Foo<string>::Function<string>(!0,
                                                                    !!0)
    IL_0059:  ldstr      "string1string2"
    IL_005e:  callvirt   instance bool [mscorlib]System.String::Equals(string)
    IL_0063:  call       void Test_method014::Eval(bool)
    IL_0068:  ldsfld     bool Test_method014::result
    IL_006d:  brfalse.s  IL_007e

    IL_006f:  ldstr      "Test Passed"
    IL_0074:  call       void [System.Console]System.Console::WriteLine(string)
    IL_0079:  ldc.i4.s   100
    IL_007b:  stloc.0
    IL_007c:  br.s       IL_008c

    IL_007e:  ldstr      "Test Failed"
    IL_0083:  call       void [System.Console]System.Console::WriteLine(string)
    IL_0088:  ldc.i4.1
    IL_0089:  stloc.0
    IL_008a:  br.s       IL_008c

    IL_008c:  ldloc.0
    IL_008d:  ret
  } // end of method Test::Main

  .method private hidebysig specialname rtspecialname static 
          void  .cctor() cil managed
  {
    // Code size       13 (0xd)
    .maxstack  1
    IL_0000:  ldc.i4.0
    IL_0001:  stsfld     int32 Test_method014::counter
    IL_0006:  ldc.i4.1
    IL_0007:  stsfld     bool Test_method014::result
    IL_000c:  ret
  } // end of method Test::.cctor

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       7 (0x7)
    .maxstack  1
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  ret
  } // end of method Test::.ctor

} // end of class Test


// =============================================================


//*********** DISASSEMBLY COMPLETE ***********************
// WARNING: Created Win32 resource file method014.res
