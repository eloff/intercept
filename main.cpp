#include <iostream>

#define INTERCEPT_ENABLED

#define INTERCEPT_CONFIG_MAIN
#include "intercept.hpp"
#undef INTERCEPT_CONFIG_MAIN
#include "intercept.hpp"

using namespace std;

int foo(int x, double y) {
	INTERCEPT("foo", int, x, y);
	return x;
}

void bar() {
	INTERCEPT("bar", void);
	throw std::logic_error("need to bypass this!");
}

int main() {
	Intercept::Context ctx;
	//f.setMock([](int i) { return i*2 + 1; });

	ctx.setMock("bar", [](Intercept::Context&) {});

	bar();

	cout << "foo=" << foo(43,12.7) << endl;
	cout << "totalCalls=" << ctx.count() << endl;
	if (!ctx.empty()) {
		for(auto& call : ctx) {
			auto hook = call.hook();
			cout << "call=" << hook->name() << " with num args=" << call.totalArgs() << endl;
		}
	}

	auto call = ctx["foo"];
	cout << "x=" << call->get<int>(0) << " y=" << call->get<double>(1) << endl;

	return 0;
}