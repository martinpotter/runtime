// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Sys
    {

        [Flags]
        internal enum InterfaceFlags
        {
            InterfaceUp = 0x01,
            InterfaceSupportsMulticast = 0x02,
            InterfaceHasLink = 0x04,
            InterfaceError = 0x08,
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public readonly struct TcpGlobalStatistics
        {
            public readonly ulong ConnectionsAccepted;
            public readonly ulong ConnectionsInitiated;
            public readonly ulong CumulativeConnections;
            public readonly ulong ErrorsReceived;
            public readonly ulong FailedConnectionAttempts;
            public readonly ulong SegmentsReceived;
            public readonly ulong SegmentsResent;
            public readonly ulong SegmentsSent;
            public readonly int CurrentConnections;
            private readonly int __padding;
        }

        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetTcpGlobalStatistics")]
        public static unsafe extern int GetTcpGlobalStatistics(TcpGlobalStatistics* statistics);

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public readonly struct IPv4GlobalStatistics
        {
            public readonly ulong OutboundPackets;
            public readonly ulong OutputPacketsNoRoute;
            public readonly ulong CantFrags;
            public readonly ulong DatagramsFragmented;
            public readonly ulong PacketsReassembled;
            public readonly ulong TotalPacketsReceived;
            public readonly ulong PacketsDelivered;
            public readonly ulong PacketsDiscarded;
            public readonly ulong PacketsForwarded;
            public readonly ulong BadAddress;
            public readonly ulong BadHeader;
            public readonly ulong UnknownProtos;
            public readonly int DefaultTtl;
            public readonly int Forwarding;
        }

        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetIPv4GlobalStatistics")]
        public static unsafe extern int GetIPv4GlobalStatistics(IPv4GlobalStatistics* statistics);

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public readonly struct UdpGlobalStatistics
        {
            public readonly ulong DatagramsReceived;
            public readonly ulong DatagramsSent;
            public readonly ulong IncomingDiscarded;
            public readonly ulong IncomingErrors;
            public readonly ulong UdpListeners;
        }

        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetUdpGlobalStatistics")]
        public static unsafe extern int GetUdpGlobalStatistics(UdpGlobalStatistics* statistics);

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public readonly struct Icmpv4GlobalStatistics
        {
            public readonly ulong AddressMaskRepliesReceived;
            public readonly ulong AddressMaskRepliesSent;
            public readonly ulong AddressMaskRequestsReceived;
            public readonly ulong AddressMaskRequestsSent;
            public readonly ulong DestinationUnreachableMessagesReceived;
            public readonly ulong DestinationUnreachableMessagesSent;
            public readonly ulong EchoRepliesReceived;
            public readonly ulong EchoRepliesSent;
            public readonly ulong EchoRequestsReceived;
            public readonly ulong EchoRequestsSent;
            public readonly ulong ParameterProblemsReceived;
            public readonly ulong ParameterProblemsSent;
            public readonly ulong RedirectsReceived;
            public readonly ulong RedirectsSent;
            public readonly ulong SourceQuenchesReceived;
            public readonly ulong SourceQuenchesSent;
            public readonly ulong TimeExceededMessagesReceived;
            public readonly ulong TimeExceededMessagesSent;
            public readonly ulong TimestampRepliesReceived;
            public readonly ulong TimestampRepliesSent;
            public readonly ulong TimestampRequestsReceived;
            public readonly ulong TimestampRequestsSent;
        }

        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetIcmpv4GlobalStatistics")]
        public static unsafe extern int GetIcmpv4GlobalStatistics(Icmpv4GlobalStatistics* statistics);

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public readonly struct Icmpv6GlobalStatistics
        {
            public readonly ulong DestinationUnreachableMessagesReceived;
            public readonly ulong DestinationUnreachableMessagesSent;
            public readonly ulong EchoRepliesReceived;
            public readonly ulong EchoRepliesSent;
            public readonly ulong EchoRequestsReceived;
            public readonly ulong EchoRequestsSent;
            public readonly ulong MembershipQueriesReceived;
            public readonly ulong MembershipQueriesSent;
            public readonly ulong MembershipReductionsReceived;
            public readonly ulong MembershipReductionsSent;
            public readonly ulong MembershipReportsReceived;
            public readonly ulong MembershipReportsSent;
            public readonly ulong NeighborAdvertisementsReceived;
            public readonly ulong NeighborAdvertisementsSent;
            public readonly ulong NeighborSolicitsReceived;
            public readonly ulong NeighborSolicitsSent;
            public readonly ulong PacketTooBigMessagesReceived;
            public readonly ulong PacketTooBigMessagesSent;
            public readonly ulong ParameterProblemsReceived;
            public readonly ulong ParameterProblemsSent;
            public readonly ulong RedirectsReceived;
            public readonly ulong RedirectsSent;
            public readonly ulong RouterAdvertisementsReceived;
            public readonly ulong RouterAdvertisementsSent;
            public readonly ulong RouterSolicitsReceived;
            public readonly ulong RouterSolicitsSent;
            public readonly ulong TimeExceededMessagesReceived;
            public readonly ulong TimeExceededMessagesSent;
        }

        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetIcmpv6GlobalStatistics")]
        public static unsafe extern int GetIcmpv6GlobalStatistics(Icmpv6GlobalStatistics* statistics);

        public readonly struct NativeIPInterfaceStatistics
        {
            public readonly ulong SendQueueLength;
            public readonly ulong Mtu;
            public readonly ulong Speed;
            public readonly ulong InPackets;
            public readonly ulong InErrors;
            public readonly ulong OutPackets;
            public readonly ulong OutErrors;
            public readonly ulong InBytes;
            public readonly ulong OutBytes;
            public readonly ulong InMulticastPackets;
            public readonly ulong OutMulticastPackets;
            public readonly ulong InDrops;
            public readonly ulong InNoProto;
            public readonly ulong Flags;
        }

        [GeneratedDllImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetNativeIPInterfaceStatistics", CharSet = CharSet.Ansi)]
        public static partial int GetNativeIPInterfaceStatistics(string name, out NativeIPInterfaceStatistics stats);

        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetNumRoutes")]
        public static extern int GetNumRoutes();
    }
}
