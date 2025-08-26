import datetime
from zoneinfo import ZoneInfo
from google.adk.agents import Agent


def get_weather(city: str) -> dict:
    """Lấy báo cáo thời tiết hiện tại cho thành phố được chỉ định.
    Args:
        city (str): Tên thành phố để lấy báo cáo thời tiết.
    Returns:
        dict: trạng thái và kết quả hoặc thông báo lỗi.
    """
    if city.lower() in ["hà nội", "hanoi", "ha noi"]:
        return {
            "status": "success",
            "report": (
                "Thời tiết ở Hà Nội hiện tại là trời nhiều mây với nhiệt độ 28 độ C "
                "(82 độ F). Độ ẩm 75%, có gió nhẹ từ hướng đông nam."
            ),
        }
    else:
        return {
            "status": "error",
            "error_message": f"Thông tin thời tiết cho '{city}' không có sẵn.",
        }


def get_current_time(city: str) -> dict:
    """Trả về thời gian hiện tại ở thành phố được chỉ định.
    Args:
        city (str): Tên thành phố để lấy thời gian hiện tại.
    Returns:
        dict: trạng thái và kết quả hoặc thông báo lỗi.
    """
    if city.lower() in ["hà nội", "hanoi", "ha noi"]:
        tz_identifier = "Asia/Ho_Chi_Minh"  # Timezone cho Việt Nam
    else:
        return {
            "status": "error",
            "error_message": (
                f"Xin lỗi, tôi không có thông tin múi giờ cho {city}."
            ),
        }

    tz = ZoneInfo(tz_identifier)
    now = datetime.datetime.now(tz)
    report = (
        f'Thời gian hiện tại ở {city} là {now.strftime("%Y-%m-%d %H:%M:%S %Z%z")}'
    )
    return {"status": "success", "report": report}


# Tạo agent
root_agent = Agent(
    name="hanoi_weather_time_agent",
    model="gemini-2.0-flash",
    description=(
        "Agent trả lời các câu hỏi về thời gian và thời tiết ở Hà Nội."
    ),
    instruction=(
        "Bạn là một agent hữu ích có thể trả lời các câu hỏi của người dùng "
        "về thời gian và thời tiết ở Hà Nội, Việt Nam."
    ),
    tools=[get_weather, get_current_time],
)
