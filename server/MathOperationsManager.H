#pragma once

#include <vector>
#include <algorithm>

namespace TLSServerNS
{

class MathOperationsManager
{
public:
    double avg(const std::vector<double>& input)
    {
        // return 1.0 * std::accumulate(v.begin(), v.end(), 0LL) / v.size();
        
        int n = 0;
        double mean = 0.0;
        for (auto x : input)
        {
            double delta = x - mean;
            mean += delta / ++n;
        }

        return mean;
    }

    double min(const std::vector<double>& input)
    {
        return *(std::min_element(input.begin(), input.end()));
    }

    double max(const std::vector<double>& input)
    {
        return *(std::max_element(input.begin(), input.end()));
    }

    double median(const std::vector<double>& input)
    {
        if (input.size() == 0)
        {
            return 0.0;
        }

        if (input.size() % 2 != 0)
            return (double)input[input.size() / 2];

        return (input[(input.size() - 1) / 2] + input[input.size() / 2]) / 2.0;
    }
};

}   // namespace TLSServerNS
