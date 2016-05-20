#ifndef INTERCEPT_ENABLED
#define INTERCEPT(name, ret, ...)
#else

#include <stdint.h>
#include <memory.h>
#include <functional>
#include <vector>
#include <unordered_map>
#include <type_traits>
#include <mutex>
#include <atomic>

namespace Intercept {
#ifndef INTERCEPT
	struct HashCString {
		inline size_t operator()(const char* s) const {
			return size_t(s);
		}
	};

	struct EqCString {
		inline bool operator()(const char* a, const char* b) const {
			return strcmp(a, b) == 0;
		}
	};
	class Context;
	class Hook;
	class Frame;
#endif
	extern std::mutex gRegisterMutex;
	extern std::unordered_map<const char *, Hook *, HashCString, EqCString> gHooks;
	extern thread_local Context* tlsCtx;
}

#define INTERCEPT(name, ret, ...) do { \
	static Intercept::Hook hook(name); \
	auto ctx = Intercept::Context::get(); \
	if (ctx && hook.enabled()) { \
		ctx->pushFrame(hook, ##__VA_ARGS__); \
		if (hook.mocked()) return hook.callMock<ret>(*ctx); }} while(0)

#ifndef INTERCEPT_STACK_BUFFER_SIZE
#define INTERCEPT_STACK_BUFFER_SIZE 524288
#endif

#ifndef INTERCEPT_CONFIG_ENABLED
#define INTERCEPT_CONFIG_ENABLED true
#endif

#ifndef INTERCEPT_CONFIG_MAIN
namespace Intercept {
	class Hook {
		const char* _name;
		std::atomic<bool> _enabled;
		std::atomic<bool> _hasMock;
		std::function<void(Context&)> mock;

	public:
		inline Hook(const char* name, bool registerHook=true) : _name(name), _enabled(INTERCEPT_CONFIG_ENABLED), _hasMock(false) {
			if (registerHook) {
				std::lock_guard<std::mutex> lock(gRegisterMutex);
				auto result = gHooks.insert(std::make_pair(name, this));
				if (!result.second) {
					Hook* existing = result.first->second;
					mock = std::move(existing->mock);
					result.first->second = this;
					_hasMock.store(existing->mocked(), std::memory_order_release);
					delete existing;
				}
			}
		}

		template<class F>
		void setMock(F&& f) {
			if (_hasMock.load(std::memory_order_acquire))
				throw std::logic_error("cannot set mock if it's already set, use clearMock first if changing it");

			mock = f;
			_hasMock.store(true, std::memory_order_release);
		}

		inline void clearMock() {
			if (!_hasMock.load(std::memory_order_acquire))
				throw std::logic_error("mock is already clear");
			_hasMock.store(false, std::memory_order_release);
			new (&mock) std::function<void(Context&)>();
		}

		template<class T>
		T callMock(Context& ctx) {
			return ((std::function<T(Context&)>*)&mock)->operator()(ctx);
		}

		inline bool mocked() const noexcept {
			return _hasMock.load(std::memory_order_acquire);
		}

		inline bool enabled() const noexcept {
			return _enabled.load(std::memory_order_relaxed);
		}

		inline bool enable() noexcept {
			return _enabled.exchange(true);
		}

		inline bool disable() noexcept {
			return _enabled.exchange(false);
		}

		inline const char* name() const noexcept {
			return _name;
		}
	};

	class FrameIterBase {
	protected:
		const Frame* frame;

	public:
		inline FrameIterBase(const Frame* frame=nullptr) : frame(frame) {}

		typedef const Frame value_type;
		typedef const Frame& reference;
		typedef const Frame* pointer;
		typedef std::forward_iterator_tag iterator_category;

		inline bool operator==(FrameIterBase other) const noexcept {
			return frame == other.frame;
		}
		inline bool operator!=(FrameIterBase other) const noexcept {
			return frame != other.frame;
		}
		inline reference operator*() const noexcept {
			return *frame;
		}
		inline pointer operator->() const noexcept {
			return frame;
		}
	};

	class PrevFrameIter : public FrameIterBase {
	public:
		using FrameIterBase::FrameIterBase;

		PrevFrameIter& operator++() noexcept;
		PrevFrameIter operator++(int) noexcept;
	};

	class NextFrameIter: public FrameIterBase {
	public:
		using FrameIterBase::FrameIterBase;

		NextFrameIter& operator++() noexcept;
		NextFrameIter operator++(int) noexcept;
	};

	class FrameList : PrevFrameIter {
		typedef const Frame value_type;
		typedef PrevFrameIter iterator;

	public:
		using PrevFrameIter::PrevFrameIter;

		iterator begin() const noexcept {
			return *this;
		}

		iterator end() const noexcept {
			return iterator();
		}

		bool empty() const {
			return frame != nullptr;
		}
	};

#pragma pack(4)
	class Frame {
		Hook& _hook;
		uint32_t _ctx;
		uint32_t _prev;
		uint16_t _argCount;
		uint16_t _size;
		uint16_t _offsets[];

	public:
		inline Frame(Context& ctx, Hook& hook, uint32_t prev, uint16_t count) :
			_hook(hook), _ctx(uint32_t(uintptr_t(this) - uintptr_t(&ctx))), _prev(prev), _argCount(count), _size(uint16_t(sizeof(Frame)) + count*2) {}

		inline Hook* hook() const {
			return &_hook;
		}

		inline Context& ctx() const {
			return *(Context*)((char*)this - _ctx);
		}

		inline uint32_t totalArgs() const {
			return _argCount;
		}

		const Frame* prev() const;
		inline const Frame* next() const {
			return (Frame*)((char*)this + _size);
		}

		template<class T>
		const T& get(uint32_t i) const {
			if (i >= _argCount)
				throw std::out_of_range("index to Frame::get<T>() out of range");

			return *(T*)((char*)_offsets + _offsets[i]);
		}

	private:
		template<class T>
		void put(uint32_t i, char* dest, /*typename std::enable_if<std::is_trivially_copyable<T>::value>::type*/T&& arg) {
			_offsets[i] = uintptr_t(dest) - uintptr_t(_offsets);
			memcpy(dest, &arg, sizeof(arg));
			_size += sizeof(arg);
		}

		friend Context;
	};
#pragma pack()

	class Context {
		std::unordered_map<uintptr_t,uint32_t> _called;
		std::vector<Hook*> _mocks;
		uint32_t _count = 0;
		uint32_t pos = 0;
		const Frame* lastFrame;
		char buf[INTERCEPT_STACK_BUFFER_SIZE];

	public:
		inline static Context* get() noexcept {
			return tlsCtx;
		}

		inline Context() : lastFrame((Frame*)buf) {
			tlsCtx = this;
		}

		inline ~Context() {
			for(auto hook : _mocks) {
				hook->clearMock();
			}
			tlsCtx = nullptr;
		}

		Context(const Context&) = delete;
		Context(Context&&) = delete;

		template<class F>
		void setMock(const char* name, F&& f) {
			auto result = gHooks.insert({name,nullptr});
			Hook* hook = result.first->second;
			if (result.second)
				result.first->second = hook = new Hook(name, false);

			hook->setMock(f);
			_mocks.push_back(hook);
		}

		Frame* createFrame(Hook& hook, size_t numArgs=0) {
			char* dest = buf+pos;
			auto result = _called.insert({uintptr_t(&hook),pos});
			auto hdrSize = uint32_t(sizeof(Frame) + numArgs*2);
			pos += hdrSize;
			if (pos >= sizeof(buf))
				throw std::out_of_range("too many frames, disable some hooks or increase INTERCEPT_STACK_BUFFER_SIZE");

			auto frame = new (dest) Frame(*this, hook, (result.second) ? 0 : result.first->second, numArgs);
			lastFrame = frame;
			_count++;
			return frame;
		}

		void pushFrame(Hook& hook) {
			createFrame(hook);
		}

		template<class... Args>
		void pushFrame(Hook& hook, Args&&... args) {
			auto frame = createFrame(hook, sizeof...(Args));
			uint32_t argIndex = 0;
			putArgs(frame, argIndex, std::forward<Args>(args)...);
		}

		template<class T, class... Args>
		void putArgs(Frame* frame, uint32_t& argIndex, T&& arg, Args&&... args) {
			putArgs(frame, argIndex++, arg);
			putArgs(frame, argIndex, std::forward<Args>(args)...);
		}

		template<class T>
		void putArgs(Frame* frame, uint32_t argIndex, T&& arg) {
			char* dest = buf+pos;
			pos += sizeof(T);
			if (pos >= sizeof(buf))
				throw std::out_of_range("too many frames, disable some hooks or increase INTERCEPT_STACK_BUFFER_SIZE");

			frame->put(argIndex, dest, arg);
		}

		inline const Frame* operator[](const char* name) const {
			auto hookIt = gHooks.find(name);
			if (hookIt == gHooks.end())
				return nullptr;

			auto it = _called.find(uintptr_t(hookIt->second));
			if (it == _called.end())
				return nullptr;

			return (const Frame*)(buf + it->second);
		}

		inline FrameList allCalls(const char* name) const {
			return FrameList((*this)[name]);
		}

		inline bool called(const char* name) const {
			return !(*this)[name];
		}

		inline uint32_t count() const noexcept {
			return _count;
		}

		inline bool empty() const noexcept {
			return _count == 0;
		}

		inline const Frame* back() {
			return lastFrame;
		}

		inline NextFrameIter begin() const {
			return NextFrameIter((Frame*)buf);
		}

		inline NextFrameIter end() const {
			return NextFrameIter(lastFrame->next());
		}

		friend Frame;
	};

	inline PrevFrameIter& PrevFrameIter::operator++() noexcept {
			frame = frame->prev();
			return *this;
	}

	inline PrevFrameIter PrevFrameIter::operator++(int) noexcept {
		auto copy = *this;
		frame = frame->prev();
		return copy;
	}

	inline NextFrameIter& NextFrameIter::operator++() noexcept {
			frame = frame->next();
			return *this;
	}

	inline NextFrameIter NextFrameIter::operator++(int) noexcept {
		auto copy = *this;
		frame = frame->next();
		return copy;
	}

	inline const Frame* Frame::prev() const {
		return (_prev == 0) ? nullptr : (Frame*)(ctx().buf + _prev);
	}
}
#else
namespace Intercept {
	thread_local Context* tlsCtx = nullptr;
	std::mutex gRegisterMutex;
	std::unordered_map<const char *, Hook *, HashCString, EqCString> gHooks;
}
#endif

#endif // ifdef INTERCEPT_ENABLED