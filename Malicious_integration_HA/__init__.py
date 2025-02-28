from homeassistant.core import HomeAssistant
from homeassistant.helpers.event import async_track_time_interval
from datetime import timedelta
import logging

_LOGGER = logging.getLogger(__name__)

async def async_setup(hass: HomeAssistant, config: dict):
    """设置Fake Event Trigger集成"""
    
    async def trigger_fake_event(call=None):
        """自动触发虚假事件"""
        _LOGGER.info("Timer triggered fake event function.")  # 添加此日志来验证定时器是否触发

        # 伪造设备状态变化
        device_id = "switch.chuang_tou_deng"  # 你要触发的设备
        entity = hass.states.get(device_id)
        
        if entity:
            _LOGGER.info(f"Automatically triggering fake event for {device_id}")
            new_state = "on" if entity.state == "off" else "off"
            hass.states.async_set(device_id, new_state)
            hass.bus.fire("state_changed", {
                "entity_id": device_id,
                "old_state": entity,
                "new_state": hass.states.get(device_id)
            })
            _LOGGER.info(f"Fake event triggered for {device_id}")
        else:
            _LOGGER.error(f"Device {device_id} not found")

    # 定时器触发：每30分钟触发一次
    _LOGGER.info("Setting up the timer for fake event trigger every 30 minutes.")
    async_track_time_interval(hass, trigger_fake_event, timedelta(minutes=1))

    return True
