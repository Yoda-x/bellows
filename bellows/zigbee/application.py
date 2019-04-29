import asyncio
import binascii
import logging
import os
from zigpy.exceptions import DeliveryError
import zigpy.application
import zigpy.device
import zigpy.util
import zigpy.zdo
import bellows.types as t
import bellows.zigbee.util
import traceback

LOGGER = logging.getLogger(__name__)


class ControllerApplication(zigpy.application.ControllerApplication):
    direct = t.EmberOutgoingMessageType.OUTGOING_DIRECT

    def __init__(self, ezsp, database_file=None):
        super().__init__(database_file=database_file)
        self._ezsp = ezsp

        self._pending = dict()
        self._multicast_table = dict()
        self._groups = set()
        self._neighbor_table = dict()
        self._child_table = dict()
        self._route_table = dict()
        self._route_table_size = 0
        self._startup = False
        self._startup_task = None
        self._watchdog_task = asyncio.ensure_future(self._watchdog())
        self._pull_frames_task = None
        self._stackversion = 0x50000 # mimimum stackversion

    def status(self):
        return [self._ezsp.status(), [
                   self._startup,
                   self._watchdog_task.done(),
                   self._pull_frames_task.done()]
                ]

    def stats(self):
        return self._ezsp.stats()

    async def _watchdog(self, wakemeup=60):
        """run in background, checks if uart restart hangs and restart as needed."""
        while True:
            try:
                await asyncio.sleep(wakemeup)
                LOGGER.debug("watchdog: running")
                if self._startup or (sum(self._ezsp.status())):
                    LOGGER.error("watchdog: startup running or failed uart restart ")
                    if self._startup_task and not self._startup_task.done():
                        self._startup_task.cancel()
                        LOGGER.warning("watchdog: cancel startup task ")
                        try:
                            await self._startup_task
                        except asyncio.CancelledError:
                            LOGGER.info("watchdog: startup terminated, catched Cancelled")
                    self._startup = False
                    self._startup_task = asyncio.ensure_future(self.startup())
            except Exception as e:
                LOGGER.info("watchdog: catched %s",  e)

    async def initialize(self):
        """Perform basic NCP initialization steps."""
        e = self._ezsp
        await asyncio.sleep(1)

        await e.reset()
        self._stackversion = await e.version()
        LOGGER.info("EZSP StackVersion : 0x%04x", self._stackversion)
        self._pull_frames_task = asyncio.ensure_future(self._pull_frames())
        c = t.EzspConfigId
        await self._cfg(c.CONFIG_STACK_PROFILE, 2)
        await self._cfg(c.CONFIG_SECURITY_LEVEL, 5)
        await self._cfg(c.CONFIG_SUPPORTED_NETWORKS, 1)
        zdo = (
            t.EmberZdoConfigurationFlags.APP_RECEIVES_SUPPORTED_ZDO_REQUESTS |
            t.EmberZdoConfigurationFlags.APP_HANDLES_UNSUPPORTED_ZDO_REQUESTS
        )
        await self._cfg(c.CONFIG_APPLICATION_ZDO_FLAGS, zdo)
        await self._cfg(c.CONFIG_TRUST_CENTER_ADDRESS_CACHE_SIZE, 2)
        await self._cfg(c.CONFIG_ADDRESS_TABLE_SIZE, 64)
        await self._cfg(c.CONFIG_SOURCE_ROUTE_TABLE_SIZE, 16)
        await self._cfg(c.CONFIG_MAX_END_DEVICE_CHILDREN, 16)
        await self._cfg(c.CONFIG_KEY_TABLE_SIZE, 16)
        await self._cfg(c.CONFIG_TRANSIENT_KEY_TIMEOUT_S, 180, True)
        if self._stackversion > 0x64ff:
            await self._cfg(c.CONFIG_END_DEVICE_POLL_TIMEOUT, 9)
            # with ezsp_callback_handlerstack 6.5 timeout changes
            # timeout_shift is gone
            # The timeout corresponding to a nonzero value N is 2^N minutes
        else:
            await self._cfg(c.CONFIG_END_DEVICE_POLL_TIMEOUT, 120)
            await self._cfg(c.CONFIG_END_DEVICE_POLL_TIMEOUT_SHIFT, 8)
        await self._cfg(c.CONFIG_APS_UNICAST_MESSAGE_COUNT, 20)
        await self._cfg(c.CONFIG_PACKET_BUFFER_COUNT, 0xff)
        self._route_table_size = await self._get(c.CONFIG_ROUTE_TABLE_SIZE)
        await self._cfg(c.CONFIG_INDIRECT_TRANSMISSION_TIMEOUT, 7700)

    async def startup(self, auto_form=False):
        """Perform a complete application startup."""
        e = self._ezsp

        if self._startup:
            LOGGER.debug("startup already running")
            return
        self._startup = True
        await self.initialize()
        await self.addEndpoint(1, 0x0104, 0x0005, [0x0020, 0x0500], [0x0020, 0x0500])
        await self.addEndpoint(13, 0xC05E, 0x0840, [0x1000, ], [0x1000, ])
        await self.addEndpoint(242, 0xA1E0, 0x0061, [0x0021, ], [0x0021, ])
        v = await e.networkInit(queue=False)
        if v[0] != t.EmberStatus.SUCCESS:
            if not auto_form:
                raise Exception("Could not initialize network")
            await self.form_network()

        v = await e.getNetworkParameters(queue=False)
        assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check
        if v[1] != t.EmberNodeType.COORDINATOR:
            if not auto_form:
                raise Exception("Network not configured as coordinator")

            LOGGER.info("Forming network")
            await self._ezsp.leaveNetwork(queue=False)
            await asyncio.sleep(1)  # TODO
            await self.form_network()

        await self._policy()
        nwk = await e.getNodeId(queue=False)
        self._nwk = nwk[0]
        ieee = await e.getEui64(queue=False)
        self._ieee = ieee[0]
        self._startup = False
        e.Run_enable()
        _groups = set(self._groups)
        await self._read_multicast_table()
        LOGGER.debug("restore groups: %s",  _groups)
        for group_id in _groups:
            await self.subscribe_group(group_id)

    async def addEndpoint(self, endpoint, profile, deviceid, input_cluster,
                          output_cluster):
        e = self._ezsp
        result = await e.addEndpoint(
                       endpoint,
                       profile,
                       deviceid,
                       0,
                       len(input_cluster),
                       len(output_cluster),
                       input_cluster,
                       output_cluster,
                       queue=False)
        LOGGER.debug("addEndpoint result: %s", result)

    async def form_network(self, channel=15, pan_id=None, extended_pan_id=None):
        channel = t.uint8_t(channel)

        if pan_id is None:
            pan_id = t.uint16_t.from_bytes(os.urandom(2), 'little')
        pan_id = t.uint16_t(pan_id)

        if extended_pan_id is None:
            extended_pan_id = t.fixed_list(8, t.uint8_t)([t.uint8_t(0)] * 8)

        initial_security_state = bellows.zigbee.util.zha_security(
                controller=True)
        v = await self._ezsp.setInitialSecurityState(initial_security_state,
                                                     queue=False)
        assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check

        parameters = t.EmberNetworkParameters()
        parameters.panId = pan_id
        parameters.extendedPanId = extended_pan_id
        parameters.radioTxPower = t.uint8_t(8)
        parameters.radioChannel = channel
        parameters.joinMethod = t.EmberJoinMethod.USE_MAC_ASSOCIATION
        parameters.nwkManagerId = t.EmberNodeId(0)
        parameters.nwkUpdateId = t.uint8_t(0)
        parameters.channels = t.uint32_t(0)

        await self._ezsp.formNetwork(parameters, queue=False)
        await self._ezsp.setValue(t.EzspValueId.VALUE_STACK_TOKEN_WRITING, 1, queue=False)
        await self._ezsp.setValue(t.EzspValueId.VALUE_MAC_PASSTHROUGH_FLAGS, 3, queue=False)

    async def _cfg(self, config_id, value, optional=False):
        v = await self._ezsp.setConfigurationValue(config_id, value, queue=False)
        if not optional:
            assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check

    async def _get(self, config_id, optional=False):
        v = await self._ezsp.getConfigurationValue(config_id, queue=False)
        if not optional:
            assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check
        return v[1]

    async def _policy(self):
        """Set up the policies for what the NCP should do."""
        e = self._ezsp
        v = await e.setPolicy(
            t.EzspPolicyId.TC_KEY_REQUEST_POLICY,
            t.EzspDecisionId.GENERATE_NEW_TC_LINK_KEY,
            queue=False
        )
        assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check
        v = await e.setPolicy(
            t.EzspPolicyId.APP_KEY_REQUEST_POLICY,
            t.EzspDecisionId.ALLOW_APP_KEY_REQUESTS,
            queue=False
        )
        assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check
        v = await e.setPolicy(
            t.EzspPolicyId.TRUST_CENTER_POLICY,
            t.EzspDecisionId.ALLOW_PRECONFIGURED_KEY_JOINS,
            queue=False
        )
        assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check

    async def force_remove(self, dev):
        # This should probably be delivered to the parent device instead
        # of the device itself.
        await self._ezsp.removeDevice(dev.nwk, dev.ieee, dev.ieee)

    def ezsp_callback_handler(self, frame_name, args):
        if frame_name == 'incomingMessageHandler':
            self._handle_frame(*args)
        elif frame_name == 'messageSentHandler':
#            if args[4] != t.EmberStatus.SUCCESS:
#                self._handle_frame_failure(*args)
#            else:
            self._handle_frame_sent(*args)
        elif frame_name == 'trustCenterJoinHandler':
            if args[2] == t.EmberDeviceUpdate.DEVICE_LEFT:
                self.handle_leave(args[0], args[1])
            else:
                self.handle_join(args[0], args[1], args[4])
        elif frame_name == 'incomingRouteRecordHandler':
            self.handle_RouteRecord(args[0], args[4])
        elif frame_name == 'incomingRouteErrorHandler':
            self._handle_incomingRouteErrorHandler(args[0], args[1])
        else:
            LOGGER.info("Unused callhander received: %s : %s",  frame_name,  args)

    async def _pull_frames(self):
        import sys
        """continously pull frames out of rec queue."""
        LOGGER.debug("Run receive queue poller")
        while True:
            frame_name, args = await self._ezsp.get_rec_frame()
#            LOGGER.debug("pulled %s", frame_name)
            if frame_name == 'ControllerRestart':
                LOGGER.debug("call startup and stop polling frames")
                self._ezsp.clear_rec_frame()
                self._startup_task = asyncio.ensure_future(self.startup())
                LOGGER.debug("Exit receive queue poller")
                break
            try:
                self.ezsp_callback_handler(frame_name, args)
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                LOGGER.debug("frame handler exception, %s", e)
                exep_data = traceback.format_exception(exc_type, exc_value,
                                                       exc_traceback)
                for e in exep_data:
                    LOGGER.debug("> %s", e)

    def _handle_frame(self, message_type, aps_frame, lqi, rssi, sender, 
            binding_index, address_index, message):
        if message_type in (t.EmberIncomingMessageType.INCOMING_MULTICAST_LOOPBACK, 
                            t.EmberIncomingMessageType.INCOMING_BROADCAST_LOOPBACK):
            LOGGER.debug("drop received broadcast/multicast from self")
            return
        try:
            device = self.get_device(nwk=sender)
        except KeyError:
            LOGGER.debug("No such device %s", sender)
            return

        device.radio_details(lqi, rssi)
        try:
            tsn, command_id, is_reply, args = self.deserialize(
                    device, aps_frame.sourceEndpoint, aps_frame.clusterId, 
                    message)
        except ValueError as e:
            LOGGER.error("Failed to parse message (%s) on cluster %d, because %s",
                    binascii.hexlify(message), aps_frame.clusterId, e)
            return

        if is_reply:
            self._handle_reply(device, aps_frame, tsn, command_id, args, 
                    message_type=message_type)
        else:
            self.handle_message(device, False, aps_frame.profileId, 
                    aps_frame.clusterId, aps_frame.sourceEndpoint, 
                    aps_frame.destinationEndpoint, tsn, command_id, args, 
                    message_type=message_type)

    def _handle_reply(self, sender, aps_frame, tsn, command_id, args, **kwargs):
        try:
            send_fut, reply_fut = self._pending[tsn]
            if send_fut.done():
                self._pending.pop(tsn)
            if reply_fut:
                reply_fut.set_result(args)
            return
        except KeyError:
            LOGGER.debug("0x%04x:%s:0x%04x Unexpected response TSN=%s command=%s args=%s ",
                         sender.nwk, aps_frame.sourceEndpoint, aps_frame.clusterId,
                         tsn, command_id, args)
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)
            # We've already handled, don't drop through to device handler
            return

        self.handle_message(sender, True, aps_frame.profileId,
                aps_frame.clusterId, aps_frame.sourceEndpoint,
                aps_frame.destinationEndpoint, tsn, command_id, args,
                **kwargs)

    def _handle_frame_failure(self, message_type, destination, aps_frame, message_tag, status, message):
        try:
            send_fut, reply_fut = self._pending.pop(message_tag)
            send_fut.set_result(status)
            send_fut.set_exception(DeliveryError("Message send failure _frame_failure: %s" % (status, )))
            if reply_fut:
                reply_fut.cancel()
        except KeyError:
            LOGGER.debug("Unexpected message send failure _frame_failure")
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)

    def _handle_frame_sent(self, message_type, destination, aps_frame, message_tag, status, message):
        try:
            send_fut, reply_fut = self._pending[message_tag]
            # Sometimes messageSendResult and a reply come out of order
            # If we've already handled the reply, delete pending
            if reply_fut is None or reply_fut.done():
                self._pending.pop(message_tag)
            send_fut.set_result(status)
        except KeyError:
            LOGGER.debug("Unexpected message send notification")
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)

    def _handle_route_record(self, *args):
        LOGGER.debug("Route Record:%s", args)

    def _handle_incomingRouteErrorHandler(self, status, nwkid):
        LOGGER.debug("Route Record ERROR:%s:%s", status, nwkid)

    async def request(self, nwk, profile, cluster, src_ep, dst_ep, sequence,
                      data, expect_reply=True, timeout=15, request_type='unicast'):
        if request_type == 'unicast':
            v = await self.urequest(nwk, profile, cluster, src_ep, dst_ep,
                                    sequence, data, expect_reply=expect_reply,
                                    timeout=timeout)
        elif request_type == 'multicast':
            v = 0
            await self.mrequest(nwk, profile, cluster, src_ep, dst_ep, sequence,
                                data, expect_reply=False, timeout=timeout)
        return v

    async def mrequest(self, nwk, profile, cluster, src_ep, dst_ep, sequence,
                       data, expect_reply=False, timeout=2):
        send_fut = asyncio.Future()
        reply_fut = None
        self._pending[sequence] = (send_fut, reply_fut)

        aps_frame = t.EmberApsFrame()
        aps_frame.profileId = t.uint16_t(profile)
        aps_frame.clusterId = t.uint16_t(cluster)
        aps_frame.sourceEndpoint = t.uint8_t(src_ep)
        aps_frame.destinationEndpoint = t.uint8_t(dst_ep)
        aps_frame.options = t.EmberApsOption(t.EmberApsOption.APS_OPTION_NONE)
        aps_frame.groupId = t.uint16_t(nwk)
        aps_frame.sequence = t.uint8_t(sequence)
        LOGGER.debug(
            "sendMultiCast to GROUP:0x%04x DST_EP:%s PROFIL_ID:%s CLUSTER:0x%04x TSN:%s, Timeout:%s",
            nwk, dst_ep, profile,  cluster, sequence, timeout,
            )
        try:
            v = await asyncio.wait_for(
                self._ezsp.sendMulticast(aps_frame, 0, 3,  sequence, data),
                timeout)
        except asyncio.TimeoutError:
            LOGGER.error(
                "Multicast uart timeout GROUP:0x%04x DST_EP:%s PROFIL_ID:%s CLUSTER:0x%04x TSN:%s, Timeout:%s",
                nwk, dst_ep, profile,  cluster, sequence, timeout,
            )
            self._pending.pop(sequence)
            send_fut.cancel()
        if v[0] != t.EmberStatus.SUCCESS:
            self._pending.pop(sequence)
            send_fut.cancel()
            LOGGER.error("Multicast send failure GROUP:0x%04x DST_EP:%s PROFIL_ID:%s CLUSTER:0x%04x TSN:%s, Timeout:%s",
                         nwk, dst_ep, profile,  cluster, sequence,  timeout,
                         )
        return v

    @zigpy.util.retryable_request
    async def urequest(self, nwk, profile, cluster, src_ep, dst_ep, sequence,
                       data, expect_reply=True, timeout=15):
#        LOGGER.debug("pending message queue length: %s", len(self._pending))

        send_fut = asyncio.Future()
        reply_fut = None
        if expect_reply:
            reply_fut = asyncio.Future()
        self._pending[sequence] = (send_fut, reply_fut)

        aps_frame = t.EmberApsFrame()
        aps_frame.profileId = t.uint16_t(profile)
        aps_frame.clusterId = t.uint16_t(cluster)
        aps_frame.sourceEndpoint = t.uint8_t(src_ep)
        aps_frame.destinationEndpoint = t.uint8_t(dst_ep)
        aps_frame.options = t.EmberApsOption(
            t.EmberApsOption.APS_OPTION_RETRY |
            t.EmberApsOption.APS_OPTION_ENABLE_ROUTE_DISCOVERY
        )
        aps_frame.groupId = t.uint16_t(0)
        aps_frame.sequence = t.uint8_t(sequence)
        LOGGER.debug(
            "sendUnicast to NWKID:0x%04x DST_EP:%s PROFIL_ID:%s CLUSTER:0x%04x TSN:%s, Timeout:%s",
            nwk, dst_ep, profile,  cluster, sequence, timeout,
            )
        try:
            v = await asyncio.wait_for(self._ezsp.sendUnicast(self.direct,
                                       nwk, aps_frame, sequence, data), timeout)
        except asyncio.TimeoutError:
            LOGGER.debug(
                "sendunicast uart timeout NWKID:0x%04x DST_EP:%s PROFIL_ID:%s CLUSTER:0x%04x TSN:%s, Timeout:%s",
                nwk, dst_ep, profile,  cluster, sequence, timeout,
            )
            self._pending.pop(sequence)
            send_fut.cancel()
            if expect_reply:
                reply_fut.cancel()
            raise DeliveryError("Message send failure uart timeout")
        if v[0] != t.EmberStatus.SUCCESS:
            self._pending.pop(sequence)
            send_fut.cancel()
            if expect_reply:
                reply_fut.cancel()
            LOGGER.debug("sendunicast send failure NWKID:0x%04x DST_EP:%s PROFIL_ID:%s CLUSTER:0x%04x TSN:%s, Timeout:%s",
                         nwk, dst_ep, profile,  cluster, sequence, timeout,
                         )
            raise DeliveryError("Message send failure _send_unicast_fail")
        try:
            v = await asyncio.wait_for(send_fut, timeout)
        except DeliveryError as e:
            LOGGER.debug("0x%04x:%s:0x%04x sendunicast send_ACK failure - Error:%s",
                         nwk, dst_ep, cluster, e)
            raise
        except asyncio.TimeoutError:
            LOGGER.debug("sendunicast message send_ACK timeout NWKID:0x%04x DST_EP:%s PROFIL_ID:%s CLUSTER:0x%04x TSN:%s, Timeout:%s",
                         nwk, dst_ep, profile,  cluster, sequence, timeout,
                         )

            self._pending.pop(sequence)
            if expect_reply:
                reply_fut.cancel()
            raise DeliveryError("ACK_TIMEOUT")
 #       if v != t.EmberStatus.SUCCESS:
 #           self._pending.pop(sequence)
 #           if expect_reply:
 #               reply_fut.cancel()
 #           LOGGER.debug("sendunicast send_ACK failure 0x%04x:%s:0x%04x = %s", nwk, dst_ep, cluster, v)
 #           raise DeliveryError("sendunicast send_ACK failure")
        if expect_reply:
            try:
                v = await asyncio.wait_for(reply_fut, timeout)
            except asyncio.TimeoutError:
                LOGGER.debug(
                        "[0x%04x:%s:0x%04x] sendunicast reply(TSN:%s) timeout failure",
                        nwk, dst_ep, cluster, sequence)
                self._pending.pop(sequence)
                raise DeliveryError("sendunicast reply timeout error")
            return v

    async def permit(self, time_s=60):
        assert 0 <= time_s <= 254
        """ send mgmt-permit-join to all router """
        await self.send_zdo_broadcast(0x0036, 0x0000, 0x00, [time_s, 0])
        return self._ezsp.permitJoining(time_s)

    async def permit_with_key(self, node, code, time_s=60):
        if type(node) is not t.EmberEUI64:
            node = t.EmberEUI64([t.uint8_t(p) for p in node])

        key = zigpy.util.convert_install_code(code)
        if key is None:
            raise Exception("Invalid install code")

        v = await self._ezsp.addTransientLinkKey(node, key)
        if v[0] != t.EmberStatus.SUCCESS:
            raise Exception("Failed to set link key")

        v = await self._ezsp.setPolicy(
            t.EzspPolicyId.TC_KEY_REQUEST_POLICY,
            t.EzspDecisionId.GENERATE_NEW_TC_LINK_KEY,
        )
        if v[0] != t.EmberStatus.SUCCESS:
            raise Exception("Failed to change policy to allow generation of new trust center keys")
        """ send mgmt-permit-join to all router """
        await self.send_zdo_broadcast(0x0036, 0x0000, 0x00, [time_s, 0])
        return self._ezsp.permitJoining(time_s, True)

    async def send_zdo_broadcast(self, command, grpid, radius, args):
        """ create aps_frame for zdo broadcast."""
        aps_frame = t.EmberApsFrame()
        aps_frame.profileId = t.uint16_t(0x0000)        # 0 for zdo
        aps_frame.clusterId = t.uint16_t(command)
        aps_frame.sourceEndpoint = t.uint8_t(0)         # endpoint 0x00 for zdo
        aps_frame.destinationEndpoint = t.uint8_t(0)   # endpoint 0x00 for zdo
        aps_frame.options = t.EmberApsOption(
            t.EmberApsOption.APS_OPTION_NONE
        )
        aps_frame.groupId = t.uint16_t(grpid)
        aps_frame.sequence = t.uint8_t(self.get_sequence())
        radius = t.uint8_t(radius)
        data = aps_frame.sequence.to_bytes(1, 'little')
        schema = zigpy.zdo.types.CLUSTERS[command][2]
        data += t.serialize(args, schema)
        LOGGER.debug("zdo-broadcast: %s - %s", aps_frame, data)
        await self._ezsp.sendBroadcast(0xfffd, aps_frame, radius, len(data), data)

    async def subscribe_group(self, group_id):
        """check if already subscribed, if not find a free entry and subscribe group_id."""

        e = self._ezsp
        index = None
        if group_id in self._groups:
            return
        else:
            self._groups.add(group_id)
        for entry_id in self._multicast_table.keys():
            if self._multicast_table[entry_id].multicastId == group_id:
                LOGGER.debug("multicast group %s already subscribed", group_id)
                return
            if self._multicast_table[entry_id].endpoint == 0:
                index = entry_id
        if index is None:
            LOGGER.critical("multicast table full,  can not add %s", group_id)
            return
        self._multicast_table[index].endpoint = t.uint8_t(1)
        self._multicast_table[index].multicastId = t.EmberMulticastId(group_id)
        result = await e.setMulticastTableEntry(t.uint8_t(index), self._multicast_table[index])
        return result

    async def unsubscribe_group(self, group_id):
        # check if subscribed and then remove
        e = self._ezsp
        self._groups.discard(group_id)
        state = 2
        for entry_id in self._multicast_table.keys():
            if self._multicast_table[entry_id].multicastId == group_id:
                self._multicast_table[entry_id].endpoint = 0
                self._multicast_table[entry_id].multicastId = 0
                (state, ) = await e.setMulticastTableEntry([entry_id, self._multicast_table[entry_id]])
        return state

    async def _read_multicast_table(self):
        # initialize copy of multicast_table, keep a copy in memory to speed up r/w
        e = self._ezsp
        entry_id = 0
        self._groups = set()
        while True:
            (state, MulticastTableEntry) = await e.getMulticastTableEntry(entry_id)
#            LOGGER.debug("read multicast entry %s status %s: %s", entry_id, state, MulticastTableEntry)
            if state == t.EmberStatus.SUCCESS:
                self._multicast_table[entry_id] = MulticastTableEntry
#                if MulticastTableEntry.endpoint:
#                    self._multicast_table["grp_index"][MulticastTableEntry.multicastId] = entry_id
            else:
                break
            entry_id += 1

    def get_neighbor(self, nwkId):
        if nwkId in self._neighbor_table["index"]:
            return self._neighbor_table.get(nwkId, None)

    async def read_neighbor_table(self):
        # initialize copy of neighbor table, keep a copy in memory to speed up r/w
        e = self._ezsp
        entry_id = 0
        self._neighbor_table = dict()
        self._neighbor_table["index"] = list()
        while True:
            try:
                (state, NeighborTableEntry) = await e.getNeighbor(entry_id)
            except DeliveryError:
                return
            if state == t.EmberStatus.SUCCESS:
                self._neighbor_table[NeighborTableEntry.shortId] = NeighborTableEntry
                self._neighbor_table["index"].append(NeighborTableEntry.shortId)
            else:
                break
            entry_id += 1
        return self._neighbor_table["index"]

    async def read_child_table(self):
        """initialize copy of child table. """

        LOGGER.debug("ReadingChildTable")
        e = self._ezsp
        entry_id = 0
        self._child_table = dict()
        self._child_table["index"] = list()
        result = await e.getParentChildParameters()
        LOGGER.debug("ChildParameters, %s", result)
        if result[0] == 0:
            return
        while entry_id < 32:
            try:
                result = await e.getChildData(entry_id)
            except DeliveryError:
                raise
            LOGGER.debug("ChildTable, %s", result)
#           if result[0] == t.EmberStatus.SUCCESS:
 #               self._child_table[ChildTableEntry.id] = ChildTableEntry
 #               self._child_table["index"].append(ChildTableEntry.id)
 #           else:
 #               break
            entry_id += 1
 #       return self._child_table["index"]

    async def read_route_table(self):
        LOGGER.debug("Reading RouteTable")
        e = self._ezsp
        entry_id = 0
        self._route_table = dict()
        self._route_table["index"] = dict()
        while entry_id < self._route_table_size:
            try:
                result = await e.getRouteTableEntry(entry_id)
            except DeliveryError:
                raise
            LOGGER.debug("RouteTable(%s) %s", entry_id, result)
            self._route_table[entry_id] = result[1]
            if not result[1].nextHop == 0:
                self._route_table["index"][result[1].destination] = entry_id
            entry_id += 1

    async def _write_multicast_table(self):
        # write copy to NCP
        pass
