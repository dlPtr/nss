#include <gtest/gtest.h>
#include <limits.h>

enum {TRUE=1, FALSE=0};

int isEven(int number)
{
    if (0 == number % 2)
        return TRUE;
    else
        return FALSE;
}

TEST(isEven, odd)
{
    EXPECT_FALSE(isEven(13));
}

TEST(isEven, even)
{
    EXPECT_TRUE(isEven(6));
}

TEST(isEven, zero)
{
    EXPECT_TRUE(isEven(0));
}

TEST(isEven, INT_MAX)
{
    EXPECT_FALSE(isEven(INT_MAX));
}

int main(int argc, char* argv[])
{
    testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
