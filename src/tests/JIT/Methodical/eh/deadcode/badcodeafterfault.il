// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.


.assembly extern System.Console
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )
  .ver 4:0:0:0
}
.assembly extern mscorlib{
  .ver 0:0:0:0
}
.assembly extern common{}
.assembly test
{
  .ver 0:0:0:0
}
.module baddcodeafterfault.exe


.class public auto ansi beforefieldinit Test_badcodeafterfault
       extends [mscorlib]System.Object
{

  .method static object GetObj() cil managed
  {
    .locals init (string str)

  try_begin:
    ldstr      "pass"
    stloc.0
    leave      try_end
  try_end:
  
    ldloc.0
    ret
    
  fault_begin:
    ldloc.0
    throw
    endfault
  fault_end:
  
    ldc.i4.0           
    ret
    
    .try try_begin to try_end 
      fault handler fault_begin to fault_end
  }


  .method public hidebysig static int32 Main() cil managed
  {
    .entrypoint
    .locals init (object V_0,
	  class [mscorlib]System.IO.StringWriter expectedOut,
	  class [common]TestUtil.TestLog testLog
    )
    
    newobj     instance void [mscorlib]System.IO.StringWriter::.ctor()
    stloc.s    expectedOut
    ldloc.s    expectedOut
    ldstr      "pass"
    callvirt   instance void [mscorlib]System.IO.TextWriter::WriteLine(string)
    ldloc.s    expectedOut
    newobj     instance void [common]TestUtil.TestLog::.ctor(object)
    stloc.s    testLog

    ldloc.s    testLog
    callvirt   instance void [common]TestUtil.TestLog::StartRecording()

    call       object Test_badcodeafterfault::GetObj()
    call       void [System.Console]System.Console::WriteLine(object)
    
    ldloc.s    testLog
    callvirt   instance void [common]TestUtil.TestLog::StopRecording()
    
    ldloc.s    testLog
    callvirt   instance int32 [common]TestUtil.TestLog::VerifyOutput()
    
    ret
  }
  
}
