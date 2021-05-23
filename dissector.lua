-- A Wireshark LUA script to do Karish Hutim

local f_tcp_len = Field.new("tcp.len")
local f_tcp_ack = Field.new("tcp.flags.ack")
local f_tcp_psh = Field.new("tcp.flags.push")
local f_tcp_syn = Field.new("tcp.flags.syn")
local f_tcp_fin = Field.new("tcp.flags.fin")
local f_tcp_rst = Field.new("tcp.flags.reset")

local f_tcp_sport = Field.new("tcp.srcport")
local f_tcp_dport = Field.new("tcp.dstport")

local f_tcp_window = Field.new("tcp.window_size")
local f_tcp_sequence = Field.new("tcp.seq")
local f_tcp_acknowledge = Field.new("tcp.ack")

local p_TCP = Proto("PCT","Power Chord Tantrum")
local F_flags = ProtoField.int32("TCP.flags","Flags")

p_TCP.fields = {F_flags}
   
function p_TCP.dissector(buffer,pinfo,tree)

	local tcp_len = f_tcp_len()
	if tcp_len then
		local tcp_ack = f_tcp_ack().value
		local tcp_psh = f_tcp_psh().value
		local tcp_syn = f_tcp_syn().value
		local tcp_fin = f_tcp_fin().value
		local tcp_rst = f_tcp_rst().value

		local tcp_sport = f_tcp_sport().value
		local tcp_dport = f_tcp_dport().value

		local tcp_window = f_tcp_window().value
		local tcp_sequence = f_tcp_sequence().value
		local tcp_acknowledge = f_tcp_acknowledge().value

        local string = "פסטן"

        if tcp_syn and tcp_ack then
            string = "אהלן, סהלן"
            goto display
        end

        if tcp_syn then
            string = "אהלן"
            goto display
        end

        if tcp_psh and tcp_ack then
            string = "רות, עבור"
            goto display
        end

        if tcp_psh then
            string = "עבור"
            goto display
        end

        if tcp_fin and tcp_ack then
            string = "רות, סוף"
            goto display
        end

        if tcp_fin then
            string = "סוף"
            goto display
        end

        if tcp_rst then
            string = "כשל"
            goto display
        end

        if tcp_ack then
            string = "רות"
            goto display
        end

        ::display::

        local subtree = tree:add(p_TCP, string)

        pinfo.cols.info = tcp_sport .. " → " .. tcp_dport .. " [" .. string .. "] Seq=" .. tcp_sequence .. " Ack=" .. tcp_acknowledge .. " Win=" .. tcp_window .. " Len=" .. tcp_len.value
	end
end

register_postdissector(p_TCP)