#include <filesystem>
#include <format>
#include <regex>
#include <sstream>
#include <pcap.h>
#include <iostream>
#include <functional>
#include <cstring>

#include "CBOEPcapParser.hpp"
#include "cfepitch.h"
#include "Config.hpp"
#include "MessageInfo.hpp"
#include "Order.hpp"
#include "OrderBookManager.hpp"
#include "OrderStore.hpp"
#include "OrderBook.hpp"
#include "DataExporter.hpp"
#include "StopWatch.hpp"
#include "Symbol.hpp"

CBOEPcapParser::CBOEPcapParser(const std::string& filename, std::size_t id)
    : m_pcapFilename{filename}, m_id{id}, m_messageInfo{}, m_orderstore{}, 
    m_dataExporter{m_id}, m_obm{&m_orderstore, &m_dataExporter}
{
    m_dataExporter.set_obm(&m_obm);
}

void CBOEPcapParser::process_message(uint64_t pktSeqNum, uint64_t msgSeqNum, const u_char *message, int msg_type)
{
    switch (msg_type)
    {
        // NON-ORDER MESSAGES
        // The following message types do not alter book state.  They may be used
        // for information purposes in some Feedhandler implementations, or may be
        // ignored altogether in other, minimalistic, implementations.

        case 0x20: // Time
        {
            /*
            From the CFE PITCH Spec:

            "A Time message is immediately generated and sent when there is a PITCH
            event for a given clock second. If there is no PITCH event for a given clock
            second, then no Time message is sent for that second. All subsequent time
            offset fields for the same unit will use the new Time value as the base
            until another Time message is received for the same unit. The Time field is
            the number of seconds relative to midnight Central Time, which is provided
            in the Time Reference message. The Time message also includes the Epoch Time
            field, which is the current time represented as the number of whole seconds
            since the Epoch (Midnight January 1, 1970)."

            Additional notes:

            Most messages contain "TimeOffset" field with nanoseconds-only part of time.
            The "seconds" part is established by this Time message.  So Feedhandler
            should keep track of this "seconds" part and update it with every Time
            message.
            */

            Time m = *(Time*)message;
            m_dataExporter.set_time_ref(m.Time);

            break;
        }

        [[unlikely]] case 0x97: // UnitClear
        {
            /*
            From the CFE PITCH Spec:

            "The Unit Clear message instructs feed recipients to clear all orders for
            the CFE book in the unit specified in the Sequenced Unit Header. It would be
            distributed in rare recovery events such as a data center fail-over. It may
            also be sent on system startup (after daily restart) when there are no
            persisted GTCs or GTDs."

            Additional notes:

            Under normal conditions, this message is never seen.
            */

            // UnitClear m = *(UnitClear*)message;
            break;
        }

        case 0xB1: // TimeReference
        {
            /*
            From the CFE PITCH Spec:

            "The Time Reference message is used to provide a midnight reference point
            for recipients of the feed. It is sent whenever the system starts up and
            when the system crosses a midnight boundary. All subsequent Time messages
            for the same unit will the use the last Midnight Reference until another
            Time Reference message is received for that unit. The Time Reference message
            includes the Trade Date, so most other sequenced messages will not include
            that information.""

            Additional notes:

            Most likely this is never needed.
            */

            TimeReference m = *(TimeReference*)message;
        
            // Parse the midnight reference date(YYYYMMDD)            
            m_dataExporter.set_date(m.MidnightReference);
        
            break;
        }

        case 0xBB: // FuturesInstrumentDefinition
        {
            /*
            From the CFE PITCH Spec:

            "The Futures Instrument Definition message can be sent as a sequenced
            message or an unsequenced message. It is sent as a sequenced message when
            the system starts up at the beginning of a trading session or if an
            instrument is created or modified during a trading day. A new sequenced
            message may be sent for a Symbol that does not visibly change any attribute.
            One un-sequenced Futures Instrument Definition message for each Symbol is
            also sent in a continuous loop, which completes approximately once every
            minute."

            Additional notes:

            In theory, new instruments may be added intra-day and their instrument
            definitions will be distributed via this message - but in practice this does
            not happen.  So there is no need to continuously listen to instrument
            definitions.  Mostly likely, these would be used just once to get instrument
            descriptions - in approximately one minute all definitions can be received.
            Or even more likely, the client system would already have all definitions
            built by a different component and stored in e.g. configuration file; in
            that case these messages can be completely ignored.
            */

            FuturesInstrumentDefinition m = *(FuturesInstrumentDefinition*)message;
            Symbol symbol(m.Symbol);

            m_obm.add_orderbook(symbol, m.ContractSize, m.PriceIncrement);
            // Pass the symbol to the data exporter for conversion to human-readable symbol
            m_dataExporter.symbol_tostring(symbol, m, message);
            break;
        }

        case 0xBE: // PriceLimits
        {
            /*
            From the CFE PITCH Spec:

            "The Price Limits message is sent out at the start of a session for products
            subject to price limits per the contract specifications. The Price Limits
            message does not signal whether price limits are in effect for that symbol;
            it simply provides those values for when they are in effect. If multiple
            Price Limits messages are received for the same Symbol, the most recent
            values will override the previous values."

            Additional notes:

            In practice, price limits are so wide that no CFE instrument has reached its
            price limits ever in the entire history of trading.  So these are of
            questionable value.  They can also be trivially calculated based on the
            prior closing price.  Nevertheless, these may be used to e.g. visualize the
            limits on the client GUI.
            */

            // PriceLimits m = *(PriceLimits*)message;
            break;
        }

        case 0xBC: // TransactionBegin
        {
            /*
            From the CFE PITCH Spec:

            "The Transaction Begin message indicates any subsequent messages, up to the
            accompanying Transaction End message, are all part of the same transaction
            block. One example of where this might be used is when a single aggressive
            order executes against several resting orders. All PITCH messages
            corresponding to such an event would be included between a Transaction Begin
            and Transaction End. It is important to note that any PITCH Message Type may
            be included in a transaction block and there is no guarantee that the
            messages apply to the same price level or even the same Symbol. Transaction
            Begin messages do not alter the book and can be ignored if messages are
            being used solely to build a book. Feed processors can use a transaction
            block as a trigger to postpone publishing a quote update until the end of
            the transaction block. In the prior example of a single aggressive order
            executing against multiple resting orders, a top of book feed would be able
            to publish a single trade message and quote update resulting from multiple
            Order Executed messages once it finished processing all of the messages
            within the transaction block."

            Additional notes:

            In practice, messages included in the TransactionBegin-TransactionEnd block
            are almost always OrderExecuted which result from one large agressor
            executing against multiple smaller resting orders - the same example as used
            in the CFE PITCH spec.  This is really a *single* match event, but due to
            system design CFE published it as multiple events - one per resting order -
            all with the same Exchange timestamp.  In practice number of messages is
            often 10 to 20 but may also reach 100 or more.  Feedhandler should
            definitely avoid publishing updates to clients before it completes
            processing of a transaction block.
            */

            // TransactionBegin m = *(TransactionBegin*)message;
            break;
        }

        case 0xBD: // TransactionEnd
        {
            /*
            See comments for TransactionBegin.
            */

            // TransactionEnd m = *(TransactionEnd*)message;
            break;
        }

        case 0x31: // TradingStatus
        {
            /*
            From the CFE PITCH Spec:

            "The Trading Status message is used to indicate the current trading status
            of a Futures contract. A Trading Status message will be sent whenever a
            security’s trading status changes. If a Trading Status has not been received
            for a symbol, then the Trading Status for the symbol should be assumed to be
            “S = Suspended”."

            Additional notes:

            These are sent for every instrument - both simple and complex (spreads).  In
            general:
            - Around 16:45 Central Time, instruments transition to "Q - Queing";
            orders can be added but no trading yet
            - Around 17:00 Central Time, instruments transition to "T - Trading";
            trading is enabled
            - Around 16:00 Central Time (next day), instruments transition to "S -
            Suspended"; trading is closed

            Note that some low-liquidity instruments, like exotic spreads or far-out
            outrights, may transition between Q and T also at seemingly random time
            during the trading day.
            */

            TradingStatus m = *(TradingStatus*)message;
            m_obm.update_tradingStatus(m.Symbol, m.TradingStatus);
            break;
        }

        case 0x2A: // TradeLong
        {
            // TradeLong m = *(TradeLong*)message;
            break;
        }
        case 0x2B: // TradeShort
        {
            /*
            From the CFE PITCH Spec:

            "The Trade message provides information about executions that occur off of
            the CFE book (such as ECRP/Block trades). Trade messages are necessary to
            calculate CFE execution data. Trade messages do not alter the book and can
            be ignored if messages are being used solely to build a book. The Order Id
            sent in a Trade message is obfuscated and will not tie back to any real
            Order Id sent back via a FIX or BOE order entry session."

            Additional notes:

            Most commonly, TradeLong/TradeShort messages are sent when a spread
            instrument trades.  CFE sends OrderExecuted for the spread itself, and
            TradeLong/TradeShort for each of the legs.  As noted in the Spec, these can
            be ignored for the purposes of book-building because the actual book which
            trades is the spread book, not the legs. They may be useful for some other
            purposes like calculating leg trading volume.  When these are sent, almost
            always they are TradeShort and not TradeLong.
            */

            // TradeShort m = *(TradeShort*)message;
            break;
        }

        case 0x2C: // TradeBreak
        {
            /*
            From the CFE PITCH Spec:

            "The Trade Break message is sent whenever an execution on CFE is broken.
            Trade breaks are rare and only affect applications that rely upon CFE
            execution-based data. A Trade Break followed immediately be a new Trade with
            the same Execution Id indicates that a trade correction has occurred.
            Applications that simply build a CFE book can ignore Trade Break messages."

            Additional notes:

            As noted, these are rare.  There are none in the reference market data file
            for trade date 2023-11-16.
            */

            // TradeBreak m = *(TradeBreak*)message;
            break;
        }

        case 0xB9: // Settlement
        {
            /*
            From the CFE PITCH Spec:

            "Settlement messages are used to provide information concerning indicative,
            approved, or corrected daily and final settlement prices for CFE products.
            An indicative daily settlement price (Issue = I) is calculated by the system
            and sent immediately after an instrument closes trading but before the
            settlement price is approved. An approved settlement price (Issue = S) is
            sent once the CFE Trade Desk approves a settlement price for an instrument.
            If there is an error in the approved settlement price, then it may be
            re-issued (Issue = R). For symbols that settle each day using VWAP, the
            system will begin disseminating an intermediate indicative price update
            (Issue = i) at 2:59:35 p.m. CT (following the first interval of the VWAP
            calculation) that will be sent every five seconds, leading up to the receipt
            of the indicative daily settlement price (Issue = I)."

            Additional notes:

            Typically these are informational-only but there may be a trading strategy
            client interested in the indicative settlement prices.  Thus, a Feedhandler
            may want to forward these to clients.
            */

            // Settlement m = *(Settlement*)message;
            break;
        }

        case 0xD3: // OpenInterest
        {
            /*
            From the CFE PITCH Spec:

            "The Open Interest message is sent to communicate a symbol’s open interest,
            usually for the prior trading date. This message will be sent when open
            interest information is made available to CFE and may be sent multiple times
            if there are changes to the open interest for a symbol. The open interest is
            also populated in the End of Day Summary message."

            Additional notes:

            Most likely these are informational-only.  Maybe a client may want to store
            these daily values into the database for some later analysis.  These may
            usually be obtained from other sources, also.
            */

            // OpenInterest m = *(OpenInterest*)message;
            break;
        }

        case 0xBA: // EndOfDaySummary
        {
            /*
            From the CFE PITCH Spec:

            "The End of Day Summary is sent immediately after trading ends for a symbol.
            No more Market Update messages will follow an End of Day Summary for a
            particular symbol. A value of zero in the Total Volume field means that no
            volume traded on that symbol for the day. The Total Volume field reflects
            all contracts traded during the day. Block, ECRP, and Derived (effective
            12/11/23) trades are included in the Total Volume field, but they are also
            reported separately to provide more detail.""

            Additional notes:

            Similar to OpenInterest, these would most likely be informational-only.  May
            be useful to store daily values to some database.
            */

            // EndOfDaySummary m = *(EndOfDaySummary*)message;
            break;
        }

        case 0x2D: // EndOfSession
        {
            /*
            From the CFE PITCH Spec:

            "The End of Session message is sent for each unit when the unit shuts down.
            No more sequenced messages will be delivered for this unit, but heartbeats
            from the unit may be received."

            Additional notes:

            Very last sequenced message on the feed.  Probably not very useful and can
            be ignored, since it's pretty clear when things shut down based on other
            data.  Perhaps could be used to double-check data integrity by verifying that
            it is indeed the last message.
            */

            // EndOfSession m = *(EndOfSession*)message;
            break;
        }

        // ORDER MESSAGES
        // The following messages do alter book state.  In order to correctly build
        // order books and maintain data integrity, it is essential to process every
        // message correctly.  Even a single missed message will likely result in
        // loss of data integrity.  Appropriate checks may and should be used in
        // code.  For instance, all of OrderExecuted, ReduceSize, ModifyOrder, and
        // DeleteOrder messages refer to the OrderId of an order which must exist;
        // if Feedhandler is not able to find such OrderId it most likely means that
        // it has missed on incorrectly processed some earlier message(s).
        // OrderExecuted should only occur to orders at the top of the FIFO queue,
        // and so on.  It is recommended that Feedhandler implements data integrity
        // checks whether in a form of asserts, exceptions, or log messages -
        // especially during the development stages while the code is not yet
        // proven.

        case 0x21: // AddOrderLong
        {
            AddOrderLong m = *(AddOrderLong *)message;
            Order::Side side = m.SideIndicator == 'B' ? Order::Side::Buy : Order::Side::Sell;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.add_order(m.OrderId, m.Symbol, m.Price, m.Quantity, side);
            break;
        }
        case 0x22: // AddOrderShort
        {
            /*
            From the CFE PITCH Spec:

            "An Add Order message represents a newly accepted visible order on the CFE
            book. It includes a day-specific Order Id assigned by CFE to the order."

            Additional notes:

            AddOrderLong/AddOrderShort is what adds orders to the books.  In the
            reference market data file, there are about 700 thousand AddOrder messages.
            Almost all of them are AddOrderShort - but once in a while CFE sends
            AddOrderLong to keep things interesting, so it cannot be ignored.  It may be
            useful to process these two together as a single message type to avoid code
            duplication.

            The first AddOrder messages for the day are typically sent around 16:07.
            These are GTC orders that are left in books being restored.  There's usually
            about 15 thousand GTC orders.  In order to maintain data integrity, it is
            essential to listen to these GTC-restoring day orders or have them in PCAP.
            Thus, a full day PCAP should start prior to this approximately 16:07 time.
            All GTC-restoring AddOrder messages have the same Exchange timestamp and are
            sent closely together, possibly at the maximum line rate of 10 Gbps.  Thus,
            15 thousand or so messages may be received during a single millisecond
            creating one of the peak daily load spikes.  It is, of course, important
            that a Feedhandler is able to process this spike and does not drop any of
            these messages.

            It may be important for client strategies to know whether orders are GTC or
            not.  So a Feedhandler may want to mark orders added during this
            GTC-restoration cycle as GTC, as opposed to DAY orders added later.

            In total, there are about 700 thousand AddOrder messages for the day.
            */
            AddOrderShort m = *(AddOrderShort *)message;
            Order::Side side = m.SideIndicator == 'B' ? Order::Side::Buy : Order::Side::Sell;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.add_order(m.OrderId, m.Symbol, m.Price, m.Quantity, side);
            break;
        }

        case 0x23: // OrderExecuted
        {
            /*
            From the CFE PITCH Spec:

            "Order Executed messages are sent when an order on the CFE book is executed
            in whole or in part. The execution price equals the limit order price found
            in the original Add Order message or the limit order price in the latest
            Modify Order message referencing the Order Id."

            Additional notes:

            CFE is strictly a First-In-First-Out (FIFO) market, so resting order
            priority is based first on price level and then on order entry time.  When
            an resting order is executed, it must be the first in the FIFO queue.  This
            fact may be used as [additional] data integrity check within the Feedhandler
            - if OrderExecuted is received for an order which is not at the top price
            level, or is on the top price level but is not front of the FIFO queue - it
            indicates a data itegrity issue.

            In total, there are about 40 thousand OrderExecuted messages for the day.
            */

            OrderExecuted m = *(OrderExecuted*)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.execute_order(m.OrderId, m.ExecutedQuantity);
            break;
        }

        case 0x25: // ReduceSizeLong
        {
            ReduceSizeLong m = *(ReduceSizeLong *)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.reduce_order(m.OrderId, m.CancelledQuantity);
            break;
        }
        case 0x26: // ReduceSizeShort
        {
            /*
            From the CFE PITCH Spec:

            "Reduce Size messages are sent when a visible order on the CFE book is
            partially reduced."

            Additional notes:

            Note that the spec says "partially reduced" - so these are sent only when
            there is an order remainder of at least 1, for example, order quantity is
            reduced from 7 to 1, and price remains the same.  On CFE, it is possible to
            send a "modify" request reducing the quantity to zero, but in that case CFE
            sends a "DeleteOrder" message rather than reduce.

            Similar to other Long/Short message flavors, ReduceSize is almost always
            ReduceSizeShort; in the reference file there are no ReduceSizeLong messages.
            However, there are no guarantees that CFE does not decide to send a
            ReduceSizeLong just for the fun of it, so both must be processed.

            There are about 30 thousand ReduceSize messages in the reference MD file.
            */

            ReduceSizeShort m = *(ReduceSizeShort *)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.reduce_order(m.OrderId, m.CancelledQuantity);
            break;
        }

        case 0x27: // ModifyOrderLong
        {
            ModifyOrderLong m = *(ModifyOrderLong *)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.modify_order(m.OrderId, m.Price, m.Quantity);

            break;
        }
        case 0x28: // ModifyOrderShort
        {
            /*
            From the CFE PITCH Spec:

            "The Modify Order message is sent whenever an open order is visibly
            modified. The Order Id refers to the Order Id of the original Add Order
            message.  Note that Modify Order messages that appear to be “no ops” (i.e.
            they do not appear to modify any relevant fields) will still lose priority."

            Additional notes:

            Similar to other Long/Short messages flavors, almost all modifies are
            ModifyOrderShort - there are about 360 thousand of them in the reference MD
            file.  But ModifyOrderLong should also be handled, and there is in fact 1 of
            those in the reference file.

            ModifyOrder represent the most complex message for book-building purposes.
            Note that ModifyOrder may modify an order's (1) price only, (2) quantity
            only, (3) both price and quantity, or (4) nothing.  Case (4) is a "no-op
            modify" mentioned in the CFE spec and results in order being sent to the end
            of the FIFO queue.
            */

            ModifyOrderShort m = *(ModifyOrderShort *)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.modify_order(m.OrderId, m.Price, m.Quantity);
            break;
        }

        case 0x29: // DeleteOrder
        {
            /*
            From the CFE PITCH Spec:

            "The Delete Order message is sent whenever a booked order is cancelled or
            leaves the order book. The Order Id refers to the Order Id of the original
            Add Order message. An order that is deleted from the book may return to the
            book later under certain circumstances. Therefore, a Delete Order message
            does not indicate that a given Order Id will not be sent again on a
            subsequent Add Order message."

            Additional notes:

            Note the second part of the above comment from PITCH spec - deleted order
            may return to the book under certain conditions.  This means that the same
            Order ID may be used *again* following the delete.  So, while Ordder IDs are
            unique among outstanding orders, they are not globally unique.

            DeleteOrder is the second-most common message after AddOrder, with about 670
            thousand DeleteOrder messages in the reference file.
            */

            DeleteOrder m = *(DeleteOrder*)message;
            m_dataExporter.set_time_offset(m.TimeOffset);
            m_dataExporter.set_packet_infos(pktSeqNum, msgSeqNum);

            m_obm.cancel_order(m.OrderId);
            break;
        }
        default:
        {
            // Handle unknown message types
            throw std::invalid_argument("Error: unrecognized message type " + std::to_string(msg_type));
        }
    }
}

void CBOEPcapParser::process_packet(const u_char *packet) noexcept
{
    /*
    All PCAP data has the following header lengths:
    Ethernet: 14 bytes
    IP      : 20 bytes
    UDP     : 8 bytes

    PITCH payload starts at byte 43.
    */
    int offset = 42;

    SequencedUnitHeader suHeader = *(SequencedUnitHeader *)(packet + offset);

    // Skip PITCH packets for Unit other than 1, unsequenced PITCH packets, and
    // those with zero messages (heartbeats)
    //(Time sequences will be reset to 1 each day when feed startup)
    if (suHeader.HdrUnit != 1 || suHeader.HdrSequence == 0 || suHeader.HdrCount == 0)
    {
        return;
    }

    uint64_t pktSeqNum = suHeader.HdrSequence;
	uint64_t msgSeqNum = suHeader.HdrSequence;

    // First message in packet
    offset += sizeof(SequencedUnitHeader);
    MessageHeader msgHeader = *(MessageHeader *)(packet + offset);
    process_message(pktSeqNum, msgSeqNum, packet + offset + 2, msgHeader.MsgType);

    // All remaining messages in packet
    for (int j = 0; j < suHeader.HdrCount - 1; j++)
    {
        ++msgSeqNum;
        offset += msgHeader.MsgLen;
        msgHeader = *(MessageHeader *)(packet + offset);
        process_message(pktSeqNum, msgSeqNum, packet + offset + 2, msgHeader.MsgType);
    }
}

void CBOEPcapParser::start()
{
    auto& config = Config::getInstance();

    StopWatch sw;
    if (config.time())
    {
        std::string name = "Day " + std::to_string(m_id) + " Time";
        sw.set_name(name);
        sw.Start();
    }

    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to store error messages
    pcap_t* pcap;                   // PCAP handle
    struct pcap_pkthdr header; // Header for packet metadata
    const u_char* packet;      // Pointer to the packet data

    // Attempt to open the provided PCAP file in offline mode
    pcap = pcap_open_offline(m_pcapFilename.c_str(), errbuf);
    if (pcap == nullptr) 
    {
        throw std::runtime_error("Error: Unable to open the file " + m_pcapFilename);
    }
    std::size_t counter = 0;

    // Process each packet in the PCAP file
    while ((packet = pcap_next(pcap, &header)) != nullptr) 
    {
        ++counter;
        process_packet(packet);

        if (config.showOB())
        {
            auto args = config.orderbook();
            std::string time = args[1] + " " + args[2];

            m_dataExporter.orderbook_printer(args[0], time);
        }
    }
    
    // Close the PCAP file
    pcap_close(pcap);

    sw.Stop();
    if (config.time())
        sw.display_time();
}

void CBOEPcapParser::messages_summary()
{
    auto& config = Config::getInstance();

    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to store error messages
    pcap_t* pcap;                   // PCAP handle
    struct pcap_pkthdr header; // Header for packet metadata
    const u_char* packet;      // Pointer to the packet data

    // Attempt to open the provided PCAP file in offline mode
    pcap = pcap_open_offline(m_pcapFilename.c_str(), errbuf);
    if (pcap == nullptr) 
    {
        throw std::runtime_error("Error: Unable to open the file " + m_pcapFilename);
    }
    // Process each packet in the PCAP file
    while ((packet = pcap_next(pcap, &header)) != nullptr) 
    {
        if (config.gaps())
            gap_helper(packet);
        if (config.msgSummary())
            messages_summary_helper(packet);
    }
    // Close the PCAP file
    pcap_close(pcap);


    if (config.gaps())
    {
        if (!m_messageInfo.packet_gaps.empty())
        {
            std::cout << "Packet gap(s) detected:\n";
            for (const auto& [expected, actual] : m_messageInfo.packet_gaps)
            {
                std::cout << "Expected packet sequence number: " << expected
                << " | Actual: " << actual << std::endl;
            }
        }
        else
        {
            std::cout << "No packet gap detected!\n" << std::endl;
        }
    }

    if (config.msgSummary())
    {
        std::cout << "Message Counts by Date and Type:" << std::endl;
        for (const auto& dateEntry : m_messageInfo.dailyMessageCounts)
        {
            if (dateEntry.first.empty())
                continue;

            std::string date = dateEntry.first;
            date.insert(4, "-");
            date.insert(7, "-");

            std::cout << "Date: " << date << std::endl;
            for (const auto& typeEntry : m_messageInfo.messageTypeInfo)
            {
                auto it = dateEntry.second.find(typeEntry.first);
                if (it != dateEntry.second.end())
                {
                    std::cout << std::format("  Type: {:<28} (0x{:02X}) - Count: {:>9}\n",
                                            typeEntry.second,
                                            static_cast<int>(typeEntry.first),
                                            it->second);
                }
                else
                {
                    std::cout << std::format("  Type: {:<28} (0x{:02X}) - Count: {:>9}\n",
                                            typeEntry.second,
                                            static_cast<int>(typeEntry.first),
                                            0);
                }
            }
        }
        std::cout << std::endl;
    }
    m_messageInfo = MessageInfo{}; // Reset the message counter
}

void CBOEPcapParser::gap_helper(const u_char *packet) noexcept
{
    int offset = 42;
    SequencedUnitHeader suHeader = *(SequencedUnitHeader *)(packet + offset);

    if (suHeader.HdrUnit != 1 || suHeader.HdrSequence == 0 || suHeader.HdrCount == 0)
    {
        return;
    }

    // Gap detection
    if (m_messageInfo.gNextExpectedPacketSeqNum)
    {
        if (suHeader.HdrSequence != m_messageInfo.gNextExpectedPacketSeqNum && suHeader.HdrSequence != 1)
        {
            unsigned int hdrSeq = suHeader.HdrSequence;
            m_messageInfo.packet_gaps.push_back({m_messageInfo.gNextExpectedPacketSeqNum, hdrSeq});
        }
    }
    m_messageInfo.gNextExpectedPacketSeqNum = suHeader.HdrSequence + suHeader.HdrCount;
}

void CBOEPcapParser::messages_summary_helper(const u_char *packet) noexcept
{
    int offset = 42;
    SequencedUnitHeader suHeader = *(SequencedUnitHeader *)(packet + offset);

    if (suHeader.HdrUnit != 1 || suHeader.HdrSequence == 0 || suHeader.HdrCount == 0)
    {
        return;
    }

    // First message in packet
    offset += sizeof(SequencedUnitHeader);
    MessageHeader msgHeader = *(MessageHeader *)(packet + offset);
    m_messageInfo.totalMessages++;
    m_messageInfo.messageCounts[msgHeader.MsgType]++;
    
    // Ensure the date entry exists in the map
    if (!m_messageInfo.dailyMessageCounts.contains(m_messageInfo.currentTradeDate)) 
    {
        m_messageInfo.dailyMessageCounts[m_messageInfo.currentTradeDate] = std::unordered_map<uint8_t, int>();
    }
    m_messageInfo.dailyMessageCounts[m_messageInfo.currentTradeDate][msgHeader.MsgType]++;
    if (msgHeader.MsgType == 0xB1) // TimeReference
    {
        TimeReference m = *(TimeReference*)(packet + offset + 2);
        m_messageInfo.currentTradeDate = std::to_string(m.TradeDate);
    }

    // All remaining messages in packet
    for (int j = 0; j < suHeader.HdrCount - 1; j++)
    {
        offset += msgHeader.MsgLen;
        msgHeader = *(MessageHeader *)(packet + offset);
        m_messageInfo.totalMessages++;
        m_messageInfo.messageCounts[msgHeader.MsgType]++;
        
        // Ensure the date entry exists in the map
        if (!m_messageInfo.dailyMessageCounts.contains(m_messageInfo.currentTradeDate)) 
        {
            m_messageInfo.dailyMessageCounts[m_messageInfo.currentTradeDate] = std::unordered_map<uint8_t, int>();
        }
        m_messageInfo.dailyMessageCounts[m_messageInfo.currentTradeDate][msgHeader.MsgType]++;

        if (msgHeader.MsgType == 0xB1) // TimeReference
        {
            TimeReference m = *(TimeReference*)(packet + offset + 2);
            m_messageInfo.currentTradeDate = std::to_string(m.TradeDate);
        }
    }
}

// ------------------ PCAP Slicer ------------------

PcapSlicer::PcapSlicer(const std::string& filename) 
    : m_pcapFilename(filename)
{}

std::string PcapSlicer::slice_pcap(const std::string& begin_time, const std::string& end_time, const std::string& output_filename)
{
    // Display the full filepath of the output 
    std::filesystem::path p = std::filesystem::absolute(output_filename);

    // Regex to check that the begin_time and end_time have good format
    const std::regex time_pattern(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$)");

    if (!std::regex_match(begin_time, time_pattern) || !std::regex_match(end_time, time_pattern)) 
    {
        throw std::invalid_argument("Invalid format for the start or end time: Expected format (ISO 8601) is 'YYYY-MM-DDTHH:MM:SS'");
    }

    std::stringstream command;
    command << "editcap -A " << begin_time << " -B " << end_time << " " << m_pcapFilename << " " << output_filename;
    
    std::cout << "\nSlicing pcap file. Executing command: " << command.str() << std::endl;
    
    int result = std::system(command.str().c_str());
    
    if (result == 0)
    {
        std::cout << "Slicing executed successfully. File was placed at: " << p << "\n\n";
        return p;
    }
    else
        throw std::invalid_argument("Failed to execute editcap command");   
}

void PcapSlicer::daily_slice()
{
    // Open the input PCAP file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(m_pcapFilename.c_str(), errbuf);
    if (pcap == nullptr)
    {
        throw std::runtime_error("Error: Unable to open the file " + m_pcapFilename);
    }

    const u_char* packet;
    struct pcap_pkthdr* header;

    // Prepare for slicing
    std::size_t dayCount = 1;
    pcap_t* pcap_out = nullptr;
    pcap_dumper_t* pcap_dumper = nullptr;

    auto open_new_output_file = [&]() 
    {
        if (pcap_out != nullptr) 
        {
            pcap_dump_flush(pcap_dumper);  // Flush any buffered data
            pcap_dump_close(pcap_dumper);  // Close previous dumper
            pcap_close(pcap_out);          // Close previous handle
        }

        pcap_out = pcap_open_dead(pcap_datalink(pcap), 65535); // Use same link-layer header type
        std::string output_file = "../day" + std::to_string(dayCount++) + ".pcap";
        pcap_dumper = pcap_dump_open(pcap_out, output_file.c_str());
        if (pcap_dumper == nullptr) 
        {
            throw std::runtime_error("Error opening output file: " + std::string(pcap_geterr(pcap_out)));
        }

        // Set a larger buffer size for the output file
        FILE* dump_file = pcap_dump_file(pcap_dumper);
        setvbuf(dump_file, NULL, _IOFBF, 4 * 1024 * 1024); // 4 MB buffer
    };

    // Open the first output file
    open_new_output_file();

    int ret;
    while ((ret = pcap_next_ex(pcap, &header, &packet)) >= 0)
    {
        if (ret == 0) 
        {
            // Timeout elapsed (should not happen in offline mode)
            continue;
        }

        // Ensure we have enough data
        int offset = 42; // Adjust if necessary
        if (header->caplen < offset + sizeof(SequencedUnitHeader)) 
        {
            continue; // Not enough data
        }

        SequencedUnitHeader suHeader;
        std::memcpy(&suHeader, packet + offset, sizeof(SequencedUnitHeader));

        // Filter packets based on header fields
        if (suHeader.HdrUnit != 1 || suHeader.HdrSequence == 0 || suHeader.HdrCount == 0)
        {
            continue;
        }

        // Check for new day or sequence reset
        if (m_gNextExpectedPacketSeqNum != suHeader.HdrSequence)
        {
            // Write current file and open a new one
            open_new_output_file();
        }

        // Update the next expected sequence number
        m_gNextExpectedPacketSeqNum = suHeader.HdrSequence + suHeader.HdrCount;

        // Write the current packet to the output file
        pcap_dump(reinterpret_cast<u_char*>(pcap_dumper), header, packet);
    }

    if (ret == -1) 
    {
        std::cerr << "Error reading the packet: " << pcap_geterr(pcap) << std::endl;
    }

    // Clean up and close files
    if (pcap_out != nullptr) {
        pcap_dump_flush(pcap_dumper);  // Ensure all data is written
        pcap_dump_close(pcap_dumper);
        pcap_close(pcap_out);
    }
    pcap_close(pcap);
}

